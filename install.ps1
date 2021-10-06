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
	$zip_archive = [System.Convert]::FromBase64String('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')
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
	$zip_archive = [System.Convert]::FromBase64String('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')
	
	$result = Update-LMFunctionCode -Code_ZipFile $zip_archive -FunctionName $UNIQUE_NAME 
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
