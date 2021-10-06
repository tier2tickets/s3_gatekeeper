# install command:
# iex ((New-Object System.Net.WebClient).DownloadString('http://xaq.io/g?{0}' -f (Get-Random)))

echo '
====================================================================================================
This script will automatically provision an AWS account for the Tier2Tickets gatekeeper application.
In doing so it will create an S3 bucket, an API gateway endpoint, a Lambda function, an IAM role,
an IAM policy, and a DynamoDB table and will configure and link them all as needed.

It requires root credentials in the form of an AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.

You can obtain those credentials by clicking "Access Keys"
here: https://console.aws.amazon.com/iam/home#security_credential
=====================================================================================================
'

$zip_archive = [System.Convert]::FromBase64String('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')

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

$UNIQUE_NAME = ''
$AWS_ACCESS_KEY_ID = ''
$AWS_REGION = ''
$AWS_SECRET_ACCESS_KEY = ''

while (-Not $UNIQUE_NAME) {

	echo ''
	while (-Not $AWS_ACCESS_KEY_ID) {
		$AWS_ACCESS_KEY_ID = Read-Host -Prompt 'Please enter your AWS_ACCESS_KEY_ID'
	}

	while (-Not $AWS_SECRET_ACCESS_KEY) {
		$AWS_SECRET_ACCESS_KEY = Read-Host -Prompt 'Please enter your AWS_SECRET_ACCESS_KEY'
	}

	while (-Not $AWS_REGION -Or -Not (Get-AWSRegion | Where-Object {$_.Region -eq $AWS_REGION}).Region) {
		$AWS_REGION = (Read-Host -Prompt 'Please enter your AWS_REGION eg: us-east-1').ToLower()
	}

	while (-Not $UNIQUE_NAME) {
		$UNIQUE_NAME = (Read-Host -Prompt 'Please enter a unique name for your gatekeeper: alphanumeric and dashes only').ToLower()
	}

	Set-AWSCredential -AccessKey $AWS_ACCESS_KEY_ID -SecretKey $AWS_SECRET_ACCESS_KEY -Scope Script
	Set-DefaultAWSRegion -Region $AWS_REGION -Scope Script

	echo ''

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
		$UNIQUE_NAME = ''
		$AWS_ACCESS_KEY_ID = ''
		$AWS_REGION = ''
		$AWS_SECRET_ACCESS_KEY = ''
	}
}

echo "+ Enabling AES256 encryption on S3 bucket"
Set-S3BucketEncryption -BucketName $UNIQUE_NAME -ServerSideEncryptionConfiguration_ServerSideEncryptionRule @{ ServerSideEncryptionByDefault=@{ ServerSideEncryptionAlgorithm="AES256" } }

echo "+ Setting s3 bucket ACL to block all public access"
Add-S3PublicAccessBlock -BucketName $UNIQUE_NAME -PublicAccessBlockConfiguration_BlockPublicAcl $true -PublicAccessBlockConfiguration_BlockPublicPolicy $true -PublicAccessBlockConfiguration_IgnorePublicAcl $true -PublicAccessBlockConfiguration_RestrictPublicBucket $true

echo "+ Setting bucket CORS Policy"
Write-S3CORSConfiguration -BucketName $UNIQUE_NAME -Configuration_Rule @{AllowedHeaders="*"; AllowedMethods="GET","HEAD"; AllowedOrigins="null"; MaxAgeSeconds=3000}

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

$account_id = (Get-STSCallerIdentity).Account

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
					"arn:aws:dynamodb:*:*:table/'+$UNIQUE_NAME+'/*",
					"arn:aws:dynamodb:*:*:table/'+$UNIQUE_NAME+'",
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

	Write-Host '+ waiting for IAM role to become available to use' -NoNewLine
	1..20 | % { Write-Host '.' -NoNewLine; Start-Sleep 1} # 8 seconds is the minimum
	echo ''

} else {
	echo "- IAM role for lambda function already exists. Skipping creation"
}

echo "+ Attaching Policies to the IAM role"
$result = Register-IAMRolePolicy -RoleName $UNIQUE_NAME -PolicyArn $policy_arn
$result = Register-IAMRolePolicy -RoleName $UNIQUE_NAME -PolicyArn 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'


if (-Not (Get-LMFunctionList | Where-Object {$_.FunctionName -eq $UNIQUE_NAME}).FunctionName){
	echo "+ Creating lambda function"
	$lambda_role_arn = (Get-IAMRole -RoleName $UNIQUE_NAME).arn
	$hmac_key = -join ((65..90) + (97..122) | Get-Random -Count 20 | % {[char]$_})
	$result = Publish-LMFunction -Code_ZipFile $zip_archive -Description "Tier2.tech s3 gatekeeper" -FunctionName $UNIQUE_NAME -Role $lambda_role_arn -Handler 'lambda_function.lambda_handler' -Runtime 'python3.8' -Environment_Variable @{
		allowed_subnets='0.0.0.0/0'
		blocked_subnets='192.168.1.0/24'
		bucket="$UNIQUE_NAME"
		debug='false'
		hmac_key="$hmac_key"
		log_table="$UNIQUE_NAME"
		log_ttl='15552000'
	}
	
} else {
	echo "- Lambda function already exists. Updating Code."
	$hmac_key = (Get-LMFunctionConfiguration -FunctionName $UNIQUE_NAME).Environment.Variables.hmac_key
	$result = Update-LMFunctionCode -ZipFile $zip_archive -FunctionName $UNIQUE_NAME 
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
	$result = Add-LMPermission -FunctionName $UNIQUE_NAME -Action "lambda:InvokeFunction" -Principal "apigateway.amazonaws.com" -StatementId "$UNIQUE_NAME-sid" -SourceArn ("arn:aws:execute-api:"+$AWS_REGION+":"+$account_id+":"+$api_id+"/*/GET/*")
	echo "+ Granted invocation permission on the lambda function to the API"
} catch [System.InvalidOperationException] {
	echo "- Could not grant invocation permission on the lambda function to the API - perhaps already granted"
}

echo ''
echo ''
echo "* here is the gatekeeper URL: https://$api_id.execute-api.$AWS_REGION.amazonaws.com/production/"
# test with https://xxxx.execute-api.xxxx.amazonaws.com/production/test?path=/test&operation=GET_Object&expires=9999999999&hmac=test
echo "* here is the gatekeeper key: $hmac_key"
echo ''
echo ''
