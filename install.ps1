# install command: iex ((New-Object System.Net.WebClient).DownloadString('http://xaq.io/g'))
echo '
====================================================================================================
This script will automatically provision an AWS account for the Tier2Tickets gatekeeper application.
In doing so it will create an S3 bucket, an API gateway endpoint, a Lambda function, an IAM role,
an IAM policy, and a DynamoDB table and will configure and link them all.

It requires root credentials in the form of an AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.

You can obtain those credentials by clicking "Access Keys"
here: https://console.aws.amazon.com/iam/home#security_credential
=====================================================================================================
'

$AWS_ACCESS_KEY_ID = ''
$AWS_SECRET_ACCESS_KEY = ''
$AWS_REGION = ''
$UNIQUE_NAME = ''

echo "+ checking if AWSPowerShell.NetCore installed..."
if (Get-Module -ListAvailable -Name AWSPowerShell.NetCore) {
    echo "+ AWSPowerShell.NetCore Module is installed."
} 
else {
    echo "- AWSPowerShell.NetCore Module is not installed. Installing..."
	Install-Module -name AWSPowerShell.NetCore -Scope CurrentUser -Force
}

Set-ExecutionPolicy RemoteSigned -Scope Process

echo "+ loading AWSPowerShell.NetCore"
Import-Module AWSPowerShell.NetCore

$init_creds = {

	echo ''
	while (-Not $AWS_ACCESS_KEY_ID) {
		$AWS_ACCESS_KEY_ID = Read-Host -Prompt 'Please enter your AWS_ACCESS_KEY_ID'
	}

	while (-Not $AWS_SECRET_ACCESS_KEY) {
		$AWS_SECRET_ACCESS_KEY = Read-Host -Prompt 'Please enter your AWS_SECRET_ACCESS_KEY'
	}

	while (-Not $AWS_REGION -Or -Not (Get-AWSRegion | Where-Object {$_.Region -eq $AWS_REGION}).Region) {
		$AWS_REGION = Read-Host -Prompt 'Please enter your AWS_REGION eg: us-east-1'
	}

	while (-Not $UNIQUE_NAME) {
		$UNIQUE_NAME = Read-Host -Prompt 'Please enter a globally unique identifier for the S3 bucket name: lowercase alphanumeric and dashes only'
	}

	Set-AWSCredential -AccessKey $AWS_ACCESS_KEY_ID -SecretKey $AWS_SECRET_ACCESS_KEY -Scope Script
	Set-DefaultAWSRegion -Region $AWS_REGION -Scope Script

}

&$init_creds

try {
	if (-Not (Get-S3Bucket | Where-Object {$_.BucketName -eq $UNIQUE_NAME}).BucketName){
		echo "+ Creating Private S3 Bucket"
		$result = New-S3Bucket -BucketName $UNIQUE_NAME -CannedACLName Private 2> $null
	} else {
		echo "- S3 Bucket already exists. Skipping creation."
	}
} catch {
	echo ''
	echo "ERROR FROM AWS:"
	echo $_.Exception.Message
	echo ''
	Write-Host -NoNewLine 'Press any key to start over';
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	echo ''
	echo ''
	&$init_creds
}

echo "+ Enabling AES256 encryption on S3 bucket"
Set-S3BucketEncryption -BucketName $UNIQUE_NAME -ServerSideEncryptionConfiguration_ServerSideEncryptionRule @{ ServerSideEncryptionByDefault=@{ ServerSideEncryptionAlgorithm="AES256" } }

echo "+ Setting s3 bucket ACL to block all public access"
Add-S3PublicAccessBlock -BucketName $UNIQUE_NAME -PublicAccessBlockConfiguration_BlockPublicAcl $true -PublicAccessBlockConfiguration_BlockPublicPolicy $true -PublicAccessBlockConfiguration_IgnorePublicAcl $true -PublicAccessBlockConfiguration_RestrictPublicBucket $true

echo "+ Setting bucket CORS Policy"
Write-S3CORSConfiguration -BucketName $UNIQUE_NAME -Configuration_Rule @{AllowedHeaders="*"; AllowedMethods="GET","HEAD"; AllowedOrigins="*"; MaxAgeSeconds=3000}

echo "+ setting bucket lifecycle policy"
Write-S3LifecycleConfiguration -BucketName $UNIQUE_NAME -Configuration_Rule @{
	Id="transition-and-expire";
	Status="Enabled";
	AbortIncompleteMultipartUpload=@{DaysAfterInitiation=7};
	Expiration=@{Days=367};
	Prefix='uploads/';
        Transitions = @(
            @{
                Days = 30
                "StorageClass"= [Amazon.S3.S3StorageClass]::StandardInfrequentAccess
            },
            @{
                Days = 120
                "StorageClass"= [Amazon.S3.S3StorageClass]::OneZoneInfrequentAccess
            }
        )
}


if (-Not (Get-IAMPolicyList -Scope 'local' | Where-Object {$_.PolicyName -eq $UNIQUE_NAME}).PolicyName){
	echo "+ Creating IAM policy for lambda function"
	$result = New-IAMPolicy -PolicyName $UNIQUE_NAME -PolicyDocument ('{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "t2tGatekeeperPolicy",
				"Effect": "Allow",
				"Action": [
					"dynamodb:*",
					"s3:*"
				],
				"Resource": [
					"arn:aws:dynamodb:::table/'+$UNIQUE_NAME+'/*",
					"arn:aws:dynamodb:::table/'+$UNIQUE_NAME+'",
					"arn:aws:s3:::'+$UNIQUE_NAME+'/*",
					"arn:aws:s3:::'+$UNIQUE_NAME+'"
				]
			}
		]
	}')
} else {
	echo "- IAM policy for lambda function already exists. Skipping creation"
}

$policy_arn = (Get-IAMPolicyList -Scope 'local' | Where-Object {$_.PolicyName -eq $UNIQUE_NAME}).Arn


if (-Not (Get-IAMRoleList | Where-Object {$_.RoleName -eq $UNIQUE_NAME}).RoleName){
	echo "+ Creating IAM role for lambda function"
	$result = New-IAMRole -Path '/service-role/' -RoleName $UNIQUE_NAME -AssumeRolePolicyDocument '{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {
					"Service": [
						"lambda.amazonaws.com"
					]
				},
				"Action": [
					"sts:AssumeRole"
				]
			}
		]
	}'
	echo "+ waiting for IAM role to become available to use"
	Start-Sleep 16 # 8 seconds is the minimum
} else {
	echo "- IAM role for lambda function already exists. Skipping creation"
}

echo "+ Attaching Policies to the IAM role"
$result = Register-IAMRolePolicy -RoleName $UNIQUE_NAME -PolicyArn $policy_arn
$result = Register-IAMRolePolicy -RoleName $UNIQUE_NAME -PolicyArn 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'


if (-Not (Get-LMFunctionList | Where-Object {$_.FunctionName -eq $UNIQUE_NAME}).FunctionName){
	echo "+ Creating lambda function"
	$lambda_role_arn = (Get-IAMRole -RoleName $UNIQUE_NAME).arn
	$zip_archive = [System.Convert]::FromBase64String('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')
	$hmac_key = -join ((65..90) + (97..122) | Get-Random -Count 20 | % {[char]$_})
	$result = Publish-LMFunction -Code_ZipFile $zip_archive -Description "Tier2.tech s3 gatekeeper" -FunctionName $UNIQUE_NAME -Role $lambda_role_arn -Handler 'lambda_function.lambda_handler' -Runtime 'python3.8' -Environment_Variable @{
		allowed_subnets='0.0.0.0/0'
		blocked_subnets='192.168.1.0/24'
		bucket=$UNIQUE_NAME
		debug='false'
		hmac_key=$hmac_key
		log_table=$UNIQUE_NAME
		log_ttl='15552000'
	}
} else {
	echo "- Lambda function already exists. Skipping Creation."
	$hmac_key = (Get-LMFunctionConfiguration -FunctionName $UNIQUE_NAME).Environment.Variables.hmac_key
}


if (-Not (Get-DDBTableList | Where-Object {$_ -eq $UNIQUE_NAME})){
	echo "+ Creating dynamodb table"
	$schema = New-DDBTableSchema
	$result = Add-DDBKeySchema -KeyName "microTime" -KeyDataType "S" -Schema $schema
	$result = New-DDBTable -TableName $UNIQUE_NAME -ReadCapacity 10 -WriteCapacity 5 -Schema $schema

	Write-Host "+ Waiting for table status to become 'active'" -NoNewLine
	while ((Get-DDBTable -TableName $UNIQUE_NAME).TableStatus -ne 'ACTIVE'){
		Start-Sleep 1
		Write-Host '.' -NoNewLine
	}
	echo ''

	echo "+ setting table TTL value"
	$result = Update-DDBTimeToLive -TableName $UNIQUE_NAME -TimeToLiveSpecification_AttributeName 'ttl' -TimeToLiveSpecification_Enabled $true

	echo "+ setting table capacity mode to On-Demand"
	$result = Update-DDBTable -TableName $UNIQUE_NAME -BillingMode 'PAY_PER_REQUEST'
	
} else {
	echo "- dynamodb table already exists. Skipping Creation."
}


echo "+ creating API Gateway"

$api_id = (Get-AGRestApiList | Where-Object {$_.name -eq $UNIQUE_NAME}).Id

if (-Not $api_id) {
	echo "+ Creating new REST API on API-Gateway"
	$result = Import-AGRestApi -Body ('{
	  "openapi": "3.0.1",
	  "info": {
		"title": "'+$UNIQUE_NAME+'",
		"version": "2019-08-26T19:27:19Z"
	  },
	  "servers": [
		{
		  "url": "https://xxxxxxxx.execute-api.us-east-1.amazonaws.com/{basePath}",
		  "variables": {
			"basePath": {
			  "default": "/production"
			}
		  }
		}
	  ],
	  "paths": {
		"/{root_dir}": {
		  "get": {
			"parameters": [
			  {
				"name": "root_dir",
				"in": "path",
				"required": true,
				"schema": {
				  "type": "string"
				}
			  }
			],
			"responses": {
			  "200": {
				"description": "200 response",
				"content": {
				  "application/json": {
					"schema": {
					  "$ref": "#/components/schemas/Empty"
					}
				  }
				}
			  }
			}
		  }
		}
	  },
	  "components": {
		"schemas": {
		  "Empty": {
			"title": "Empty Schema",
			"type": "object"
		  }
		}
	  }
	}')

	$api_id = (Get-AGRestApiList | Where-Object {$_.name -eq $UNIQUE_NAME}).Id
} else {
	echo "- The REST-API already exists on API-Gateway. Skipping creation"
}


echo "+ Associating lambda function with API endpoint"
$api_resource_id = (Get-AGResourceList -RestApiId $api_id | Where-Object {$_.Path -eq '/{root_dir}'}).Id
$lambda_arn = (Get-LMFunctionConfiguration -FunctionName $UNIQUE_NAME).FunctionArn
$result = Write-AGIntegration -HttpMethod 'GET' -IntegrationHttpMethod 'POST' -ResourceId $api_resource_id -RestApiId $api_id -Type 'AWS_PROXY' -Uri ("arn:aws:apigateway:$AWS_REGION" + ":lambda:path/2015-03-31/functions/$lambda_arn/invocations")

$deployment_id = (Get-AGDeploymentList -RestApiId $api_id).Id
if (-Not $deployment_id){
	echo "+ Creating a new 'production' deployment stage for the API"
	$result = New-AGDeployment -RestApiId $api_id
	$deployment_id = (Get-AGDeploymentList -RestApiId $api_id).Id
	$result = New-AGStage -RestApiId $api_id -StageName 'production' -DeploymentId $deployment_id
} else {
	echo "- API deployment ID already exists, so skipping creation of 'production' deployment stage"
}


Try{ 
	$result = Add-LMPermission -FunctionName $UNIQUE_NAME -Action "lambda:InvokeFunction" -Principal "apigateway.amazonaws.com" -StatementId "$UNIQUE_NAME-statement" -SourceArn ("arn:aws:execute-api:"+$AWS_REGION+":"+$account_id+":"+$api_id+"/*/GET/*")
	echo "+ Granted invocation permission on the lambda function to the API"
} catch [System.InvalidOperationException] {
	echo "- Could not grant invocation permission on the lambda function to the API - perhaps already granted"
}

echo ''
echo ''
echo "* here is the endpoint URL: https://$api_id.execute-api.$AWS_REGION.amazonaws.com/production"
# test with https://xxxx.execute-api.xxxx.amazonaws.com/production/test?path=/test&operation=GET_Object&expires=9999999999&hmac=test
echo "* here is the secret key: $hmac_key"
echo ''
echo ''
