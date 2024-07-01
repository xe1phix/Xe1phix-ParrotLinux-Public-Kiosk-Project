## Cheatsheet: aws cli
#### Add pub key to profile & region
```aws --profile $profilename --region $regionname ec2 import-key-pair --key-name $keyname --public-key-material file://path/to/pub/key```

### EC2
#### Get overview of systems up in your account
```
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,KeyName,PublicIpAddress,SecurityGroups[0].GroupName]' --output table
```

#### Get all public IP's of systems with a certain tag
```
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[PublicIpAddress]' --output text --filter "Name=tag:**tagkey**,Values=**tagvalue**"
```

#### List security groups per instance ID
```aws --output text ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,NetworkInterfaces[*].Groups[*]]' ```

#### Show the console output from a specific instance
```aws ec2 get-console-output --instance-id $instanceid```

#### Copy AMI to different region
```aws ec2 copy-image --source-image-id ami-<id> --source-region us-east-1 --region ap-northeast-1 --name "$ec2_name"```

#### Import OVA as AMI
```aws --profile $your_profile --region $region_to_upload ec2 import-image --description "$your_description" --license-type BYOL --disk-containers file://containers.json --role-name $your_rolename_to_use```

example containers record
```
[
  {
    "Description": "Your description",
    "Format": "ova",
    "UserBucket": {
        "S3Bucket": "$S3_bucket_you_uploaded_the_ova_to",
        "S3Key": "$filename.ova"
    }
}]

```

### Lambda
#### List Lambda functions
```aws lambda list-functions```

#### Add or update a Lambda function with a ZIP file
```aws lambda update-function-code --function-name MyLambdaFunction --zip-file fileb://package.zip```

### Route53
#### Change Route53 record sets for API gateway
```aws route53 change-resource-record-sets --hosted-zone-id $yourdomainhostedzoneid --change-batch file://setup-dns-record.json```

example dns record
```
{
  "Comment": "alias api gateway to custom domain",
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "api.example.com",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "$apigatewayhostedzoneid",
          "DNSName": "yourapigateway.execute-api.us-west-1.amazonaws.com",
          "EvaluateTargetHealth": false
        }
      }
    }
  ]
}

```

#### Additional reading
https://forums.aws.amazon.com/thread.jspa?threadID=269585&tstart=0

https://docs.aws.amazon.com/general/latest/gr/rande.html#apigateway_region

https://blyx.com/2016/03/11/forensics-in-aws-an-introduction/

https://docs.aws.amazon.com/vm-import/latest/userguide/vmimport-image-import.html
