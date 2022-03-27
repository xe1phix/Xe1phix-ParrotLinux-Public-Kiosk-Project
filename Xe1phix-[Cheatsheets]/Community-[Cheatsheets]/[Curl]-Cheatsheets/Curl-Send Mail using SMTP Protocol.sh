## Send Mail using SMTP Protocol

## cURL can also be used to send mail using the SMTP protocol. 
## You should specify the from-address, to-address, and the mailserver ip-address as shown below.
curl --mail-from $blah@$test.com --mail-rcpt $foo@$test.com smtp://$mailserver.com
