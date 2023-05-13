# Splunk BOTSv3 AWS S3 & WINEvent Challenges 

<h2>AWS S3 Bucket Challenge</h2>

Today I will be finishing up my Splunk course with 2 more blue team CTFs. The first challenge is a compromised S3 bucket due to a security misconfiguration. My first task is to find out who enabled public access to the bucket as well as the bucket name.
<br>
<br>
Search string: <b>sourcetype="aws:cloudtrail" eventName="PutBucketAcl"</b>
<br>
<br>
<img src="https://i.imgur.com/eAKSWD1.jpg">
<br>
<br>
Next, I must find the event ID of the API call involved in the enabling of the S3 bucket. For this one I just looked at the log entry before the previous where I found the user and bucket name. 
<br>
<br>
Search string: <b>sourcetype="aws:cloudtrail" user_arn="arn:aws:iam::622676721278:user/bstoll" app=AwsApiCall eventName="PutBucketAcl"</b>
<br>
<br>
<img src="https://i.imgur.com/Lq1UTfw.jpg">
<br>
<br>
There is a possibility that someone from outside of the organization may have uploaded files before the IAM team could revoke the privileges. It is my task to investigate. 
<br>
<br>
Search string: <b>sourcetype="aws:s3:accesslogs" http_method=PUT bucket_name=frothlywebcode</b>
<br>
<br>
<img src="https://i.imgur.com/BGBrBPu.jpg">
<br>
<br>
There was also a compressed file that was uploaded to the bucket while it had open permissions, I need to inspect the files size. 
<br>
<br>
Search string: <b>sourcetype="aws:s3:accesslogs" frothly_html_memcached.tar.gz bytes=*</b>
<br>
<br>
Finally, they would like me to search for the source IP of the entity that uploaded the compressed file. 
<br>
<br>
Search string: <b>sourcetype="aws:s3:accesslogs" http_method=PUT bucket_name=frothlywebcode src_ip="*"</b>
<br>
<br>
<img src="https://i.imgur.com/Nl4PoZP.jpg">
<br>
<br>
<h2>WINEvent Log Challenge</h2>
<br>
This brewing company is a mess. They are now dealing with some malicious activity on their Windows endpoints, and I am tasked with getting to the bottom of it. I must seek out the endpoint that was compromised and inspect a new user creation. The WinEvent code for new account creation is 4720, so we’ll start with that.  
<br>
<br>
Search string: <b>sourcetype="wineventlog" EventCode = 472</b>
<br>
<br>
<img src="https://i.imgur.com/Kl89xc0.jpg">
<br>
I now must find the new user’s password. This took me quite some time, because there is no way to search outright for passwords in the clear. So, I went ahead and searched the host machine that the new account was created on, then the time and date from the prior account creation as well as the process command line. 
<br>
<br>
Search string: <b>sourcetype="wineventlog" host="FYODOR-L" 08/19/2018 22:08:17 PM Process_Command_Line="*"</b>
<br>
<br>
<img src="https://i.imgur.com/6uTZYx6.jpg">
<br>
To wrap this up they’d like to know one of the group names that the new malicious account was added to. Here we can search for the WINEvent code 4732, which is, “A member was added to a security enabled group.” 
<br>
<br>
Search string: <b>sourcetype="wineventlog" EventCode=4732 user_name=svcvnc</b>
<br>
<br>
<img src="https://i.imgur.com/H806Bvj.jpg">


































