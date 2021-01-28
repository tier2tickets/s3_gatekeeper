## The S3 Gatekeeper



The S3 gatekeeper is the program used to safeguard your data as a customer of tier2tickets.com. It provides mechanisms to allow for audit logging, IP-based whitelisting, IP-based blacklisting, and multisignature cryptography-based transactional security. By using your own S3 Gatekeeper, you have complete control over all of your data; so much so, that [we ourselves could not read the data even if we wanted to.](https://community.tier2tickets.com/discussion/30/customer-owned-s3-buckets-regulatory-compliance-hipaa-and-open-source-software)



**Installation:**

1. Open a PowerShell window (not a command prompt window)

2. Paste the following command into the window:

   `iex ((New-Object System.Net.WebClient).DownloadString('http://xaq.io/g?{0}' -f (Get-Random)))`

3. Press enter and follow the prompts.

**You will need a few peices of infomation to continue.** 
  * Root credentials to the account in the form of an AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. You can find/create a new set of keys on this page https://console.aws.amazon.com/iam/home#security_credential under the Access Keys tab.
  * Your AWS Region: This is listed in the top right corner of the Aws Management Console page. Click on the location dropdown to see the region names.
  * A unique name for your gatekeeper/s3 bucket. Something like HDB-BUSINESSNAME-S3. Make sure this name contains only alphanumeric characters and dashes (-).



**Prerequisites:**

None

