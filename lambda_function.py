import json
import boto3
import traceback
import os
import ipaddress
import datetime
import time
import base64
import hmac
import hashlib

allowed_subnets	= os.environ['allowed_subnets'].split(',')	# csv of cidr notation
blocked_subnets	= os.environ['blocked_subnets'].split(',')	# csv of cidr notation
bucket			= os.environ['bucket']						# s3 bucket name
log_table		= os.environ['log_table']					# dynamodb table name
log_ttl 		= os.environ['log_ttl']				    	# how many seconds to store the log entry
debug			= os.environ['debug'] 						# 'true' or false
hmac_key		= os.environ['hmac_key']					# must match what's in the user table

def lambda_handler(event, context):

	try:
		root = event['path'].strip('/') # the "folder" where uploads are stored
		sourceIp = event['requestContext']['identity']['sourceIp']
		userAgent = event['requestContext']['identity']['userAgent']
		
		
		if not event['queryStringParameters'] or not 'path' in event['queryStringParameters']:
			return {
				'statusCode': 400,
				'body': json.dumps({'msg': "Bad Request: missing 'path' param", 'error': True}),
				'headers': {	'Access-Control-Allow-Origin': '*',
								'Cache-Control': 'no-store, must-revalidate',
				},
			}
			
		path = event['queryStringParameters']['path']
		subroot = path.split('/')[1]
		
		if not 'operation' in event['queryStringParameters'] or (event['queryStringParameters']['operation'] != 'GET_Object' and event['queryStringParameters']['operation'] != 'GET_Bucket' and event['queryStringParameters']['operation'] != 'PUT_Object'):
			return {
				'statusCode': 400,
				'body': json.dumps({'msg': "Bad Request: invalid 'operation' param", 'error': True}),
				'headers': {	'Access-Control-Allow-Origin': '*',
								'Cache-Control': 'no-store, must-revalidate',
				},
			}
			
		operation = event['queryStringParameters']['operation']
		
		if not 'expires' in event['queryStringParameters']:
			return {
				'statusCode': 400,
				'body': json.dumps({'msg': "Bad Request: missing 'expires' param", 'error': True}),
				'headers': {	'Access-Control-Allow-Origin': '*',
								'Cache-Control': 'no-store, must-revalidate',
				},
			}
			
		if not 'hmac' in event['queryStringParameters']:
			return {
				'statusCode': 400,
				'body': json.dumps({'msg': "Bad Request: missing 'hmac' param", 'error': True}),
				'headers': {	'Access-Control-Allow-Origin': '*',
								'Cache-Control': 'no-store, must-revalidate',
				},
			}
			
			
		if operation == 'GET_Bucket':
			if not path.startswith('/') or not path.endswith('/') or not len(path) >= 3:
				return {
					'statusCode': 400,
					'body': json.dumps({'msg': "Bad Request: 'path' param must begin and end with '/' and be at least 3 characters", 'error': True}),
					'headers': {	'Access-Control-Allow-Origin': '*',
									'Cache-Control': 'no-store, must-revalidate',
					},
				}
		
		expires = event['queryStringParameters']['expires']
		correct_hmac = hmac.new(hmac_key.encode(), (root + subroot + operation + expires).encode(), hashlib.sha256).hexdigest()
		provided_hmac = event['queryStringParameters']['hmac']
		if not correct_hmac==provided_hmac:
			logEvent(userAgent, sourceIp, True, path, operation, "Unauthorized: invalid 'hmac' param", 401)
			return {
				'statusCode': 401,
				'body': json.dumps({'msg': "Unauthorized: invalid 'hmac' param", 'error': True}),
				'headers': {	'Access-Control-Allow-Origin': '*',
								'Cache-Control': 'no-store, must-revalidate',
				},
			}
			
		if int(event['queryStringParameters']['expires']) + 60 < int(time.time()):
			logEvent(userAgent, sourceIp, True, path, operation, 'Expired', 410)
			return {
				'statusCode': 410,
				'body': json.dumps({'msg': 'Expired', 'error': True}),
				'headers': {	'Access-Control-Allow-Origin': '*',
								'Cache-Control': 'no-store, must-revalidate',
				},
			}
		
		headers_lc = dict((k.lower(), v.lower()) for k,v in event['headers'].items())
		if debug != 'true' and (not 'origin' in headers_lc or not (headers_lc['origin'].endswith('helpdeskbuttons.com') or headers_lc['origin'].endswith('tier2tickets.com') or headers_lc['origin'] == 'api-request')):
			logEvent(userAgent, sourceIp, True, path, operation, "Forbidden: bad origin", 403)
			return {
				'statusCode': 403,
				'body': json.dumps({'msg': "Forbidden: bad origin", 'error': True}),
				'headers': {	'Access-Control-Allow-Origin': '*',
								'Cache-Control': 'no-store, must-revalidate',
				}
			}
		
		requesterIp = ipaddress.ip_address(sourceIp)
		blocked = True
		for subnet in allowed_subnets:
			allowed_subnet = ipaddress.ip_network(subnet)
			if requesterIp in allowed_subnet:
				blocked = False
				
		for subnet in blocked_subnets:
			blocked_subnet = ipaddress.ip_network(subnet)
			if requesterIp in blocked_subnet:
				blocked = True

		# PUT_Object operations should not be blocked by the ip list, that would get unruly to manage.
		if blocked and operation != 'PUT_Object':
			logEvent(userAgent, sourceIp, True, path, operation, "Forbidden: ACL", 403)
			return {
				'statusCode': 403,
				'body': json.dumps({'msg': "Forbidden: ACL", 'error': True}),
				'headers': {	'Access-Control-Allow-Origin': '*',
								'Cache-Control': 'no-store, must-revalidate',
				},
			}
			
		s3Client = boto3.client('s3')
		
		if operation == 'GET_Object':
			
			url = s3Client.generate_presigned_url('get_object', Params = {'Bucket': bucket, 'Key': root + path}, ExpiresIn = 60)
			
			logEvent(userAgent, sourceIp, False, path, operation, "Success", 302)
			return {
				'statusCode': 302,
				'body': json.dumps({'msg': "Success", 'url': url, 'error': False}),
				'headers': {	'Location': url,
								'Access-Control-Allow-Origin': '*',
								'Cache-Control': 'no-store, must-revalidate',
				}
			}
		
		if operation == 'GET_Bucket':

			response = s3Client.list_objects_v2(Bucket = bucket, Prefix = root + path)
			contents = []
			
			if 'Contents' in response:
				contents_verbose = response['Contents']
				for item in contents_verbose:
					if item['Size'] > 0:
						contents.append(item['Key'][len(root):])
						
			logEvent(userAgent, sourceIp, False, path, operation, "Success", 200)
			return {
				'statusCode': 200,
				'body': json.dumps({'msg': "Success", 'contents': contents, 'error': False}),
				'headers': {	'Access-Control-Allow-Origin': '*',
								'Cache-Control': 'no-store, must-revalidate',
				},
			}
			
			
		if operation == 'PUT_Object':
			
			utc_now = datetime.datetime.utcnow()
			amzdate = utc_now.strftime('%Y%m%dT%H%M%SZ')
			datestamp = utc_now.strftime('%Y%m%d')
			utc_expire = utc_now + datetime.timedelta(hours=1) # give them 1 hour to complete the upload
			expireTime = utc_expire.strftime('%Y-%m-%dT%H:%M:%S.000Z')
			
			toReturn = {}
			toReturn['clientReturn'] = {}
			toReturn['clientReturn']['X-Amz-Credential'] = os.environ['AWS_ACCESS_KEY_ID'] + '/' + datestamp + '/' + os.environ['AWS_REGION'] + '/s3/aws4_request'
			toReturn['clientReturn']['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256'
			toReturn['clientReturn']['X-Amz-Date'] = amzdate
			toReturn['clientReturn']['key'] = root + path
			toReturn['clientReturn']['Cache-Control'] = 'no-store, must-revalidate'
			toReturn['clientReturn']['x-amz-security-token'] = os.environ['AWS_SESSION_TOKEN']
			toReturn['bucket'] = bucket
			
			policy = dict()
			policy['expiration'] = expireTime
			policy['conditions'] = list()
			policy['conditions'].append({"bucket": bucket})
			policy['conditions'].append(["eq", "$key", toReturn['clientReturn']['key']])
			policy['conditions'].append({"x-amz-credential": toReturn['clientReturn']['X-Amz-Credential']})
			policy['conditions'].append({"x-amz-algorithm": "AWS4-HMAC-SHA256"})
			policy['conditions'].append({"x-amz-date": amzdate })
			policy['conditions'].append(["starts-with", "$x-amz-meta-requestId", ""])
			policy['conditions'].append({'Cache-Control': toReturn['clientReturn']['Cache-Control']})
			policy['conditions'].append({"x-amz-security-token": os.environ['AWS_SESSION_TOKEN']})
			policy = json.dumps(policy)
			policy = policy.encode() #string to bytes
			
			encoded_policy = base64.b64encode(policy)
			encoded_policy = encoded_policy.decode() # bytes to string
			signing_key = getSignatureKey(os.environ['AWS_SECRET_ACCESS_KEY'], datestamp, os.environ['AWS_REGION'], 's3')
			signature = hmac.new(signing_key, (encoded_policy).encode(), hashlib.sha256).hexdigest()


			toReturn['clientReturn']['Policy'] = encoded_policy
			toReturn['clientReturn']['X-Amz-Signature'] = signature
			toReturn['clientReturn']['x-amz-meta-last'] = None
			toReturn['clientReturn']['x-amz-meta-requestId'] = None

			toReturn['msg'] = "Success"
			toReturn['error'] = False
			
			logEvent(userAgent, sourceIp, False, path, operation, "Success", 200)
			return {
				'statusCode': 200,
				'body': json.dumps(toReturn),
				'headers': {	'Access-Control-Allow-Origin': '*',
								'Cache-Control': 'no-store, must-revalidate',
				},
			}
			

	except:
		
		if debug == 'true':
			return {
				'statusCode': 500,
				'body': json.dumps({'msg': traceback.format_exc(), 'error': True}),
				'headers': {	'Access-Control-Allow-Origin': '*',
								'Cache-Control': 'no-store, must-revalidate',
				},
			}
		else:
			return {
				'statusCode': 500,
				'body': json.dumps({'msg': 'Internal Exception', 'error': True}),
				'headers': {	'Access-Control-Allow-Origin': '*',
								'Cache-Control': 'no-store, must-revalidate',
				},
			}
			
			
def logEvent(userAgent, sourceIp, blocked, path, operation, msg, statusCode):
	dynamodb = boto3.resource('dynamodb')
	logtable = dynamodb.Table(log_table)
	logtable.put_item(Item = {
		'microTime': str(datetime.datetime.now()),
		'userAgent': userAgent,
		'sourceIp': sourceIp,
		'blocked': blocked,
		'path': path,
		'operation': operation,
		'ttl': int(log_ttl) + int(time.time()),
		'msg': msg,
		'statusCode': statusCode
	})

def getSignatureKey(key, dateStamp, regionName, serviceName):
	kDate = sign(('AWS4' + key).encode(), dateStamp)
	kRegion = sign(kDate, regionName)
	kService = sign(kRegion, serviceName)
	kSigning = sign(kService, 'aws4_request')
	return kSigning

def sign(key, msg):
	return hmac.new(key, msg.encode(), hashlib.sha256).digest()
