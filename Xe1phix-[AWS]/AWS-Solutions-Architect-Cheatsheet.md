# AWS Solutions Architect - Associate Notes

## EC2

- `EC2` Uptime SLA is `99.95%` within a region
- `AMIs` are not accessible across Regions, so you need to use the Console or CLI/SDK to copy AMIs between Regions.

### AMIs

- AWS does not copy launch permissions, user-defined tags, or Amazon S3 bucket permissions from the source AMI to the new AMI when you copy an Amazon Machine Image (AMI) within or across AWS Regions

### Reserved Instances (RI)

- Provides up to `75%` discount
- `Convertible` RI
  - Have the flexibility to change `family`, `OS types`, and `tenancies`
  - Cannot be sold on the Reserved Instance Marketplace

## Load Balancers

- The Classic uses a `Round-Robin` strategy for TCP listeners only
- The ALB 1st selects a target based on the routing rule, then uses a `Round-Robin` strategy to select a node
- The NLB does not uses a `Round-Robin` strategy

### Classic Load Balancer

- Supports `HTTP`, `HTTPS`, `TCP`, and `SSL` protocols

## Route 53

- Domain registration, DNS routing, and health checking

## S3

- By default, there is a limit of `100` buckets per account
- Bucket name restrictions

  - Between `3` and `63` characters long
  - Only `lower-case` characters, `numbers`, `periods`, and `dashes`
  - Must start with a `lowercase` letter or `number`
  - Cannot contain underscores, end with a dash, have consecutive periods, or use dashes adjacent to periods
  - Cannot be formatted as an IP address (`198.51.100.24`)

- Sorage Classes

  > Data is regionally redundant except `ONEZONE_IA`

  > Durability is always `99.999999999%` (11 nines) except `S3-RRS` it is `99.99%`

  - `ONEZONE_IA` (OneZonal Infrequently Accessed)
    - Less available and less resilient (`99.50%` availability)
  - `STANDARD_IA` (Standard Infrequently Accessed)
    - More available and resilient (`99.9%` availability)
    - Charges for 128 KB per object (even if the object is less than 128 KB)
  - `RRS` (Reduced Redundancy Storage)
    - Not recommended for new projects in some AWS regions
    - Offers only `99.99%` durability, so you have to design your application to re-create any objects that may be lost
  - `Glacier` data can be restored within `3-5 hours` (can be expedited to `minutes`)
  - `Glacier Deep Archive` data can be restored within `12 hours`

- `Multipart Upload`
  - Delivers the ability to begin an upload before you know the final object size
  - Delivers quick recovery from network issues
  - Delivers the ability to pause and resume object uploads
  - Delivers improved throughput
  - Provides options for more robust file upload in addition to handling larger files than single part upload
- `Transfer Acceleration` expedites uploads from the Internet to S3 by writing directly to an Edge Location
- The `Pre-Signed` URLs are useful if you want your user/customer to be able to upload a specific object to your bucket, but you don't require them to have AWS security credentials or permissions

## S3-Glacier

- Objects can be restored through `S3` CLI or API

## VPC

- By default, all accounts are limited to 5 Elastic IP addresses per region

### NAT Instances

- If the instance is too small, it might not be able to handle the network traffic

### VPC Peering

- Does not support `edge-to-edge` routing

### Network ACL

- Rules are applied to subnets and all instances within the subnet
- `Allow` & `Deny` rules are supported
- Rules are stateless, traffic for `ingress` & `egress` must be declared in rules
- Rules are processed in order to determine what traffic is permitted

## Databases

### RDS

- Supports

  - `MySQL`
  - `Aurora`
  - `PostgreSQL`

- Read Replicas for `MySQL` and `MariaDB` support Multi-AZ deployment
- Read Replicas are supported by Amazon `Aurora`, Amazon `RDS` for `MySQL`, `MariaDB`, `PostgreSQL`, and `Oracle`
- Backup retention period between `0 and 35 days`
  - `0` disables automated backups
  - `default` is `7 days` if you created the DB instance using the `Console`
  - `default` is `1 day` if you created the DB instance using `RDS API` or `AWS CLI`
- When you elect to convert RDS instance from `Single-AZ` to `Multi-AZ`, the following happens
  1. A snapshot of your primary instance is taken
  2. A new standby instance is created in a different Availability Zone
  3. From the snapshot, synchronous replication is configured between primary and standby instances
- Multi-AZ RDS deployment will automatically fail-over as a result of
  - Complete failure of the primary instance
  - Loss of availability in primary AZ
  - Loss of network connectivity in the primary AZ
- Updates are applied to your Read Replica(s) after they occur on the source DB Instance using `Asynchronous Replication`

### Placement Groups

- `cluster placement group`
  - Cannot span multiple `AZ`
  - Can span `VPCs`
- `spread placement group` cannot use dedicated instances or hosts

## Storage

- `EBS` Uptime SLA is `99.95%` within a region
- SSD volumes must be between `1 GiB - 16 TiB`
- `EBS` volumes is automatically and redundantly stored in multiple physical volumes in the same availability zone at no additional charge
- `gp2` delivers up to 16,000 IOPS
- `Instance Store`
  - Can provide very high performance but it's ephemeral. Extra precautions would be needed to ensure recovery in the event that the instance itself failed
  - Ideal for temporary contents (e.g. buffers, caches, and scratch data)
- Snapshots are constrained to the `Region` in which they were created. To share a snapshot with another `Region`, copy the snapshot to that `Region`
- `EFS` can scale to thousands of concurrent connections. However there are design limits including how many `locks` can be placed against any single file. When you see faults occurring at intervals common binary steps (e.g. 8, 16, 32, 64, etc) always be suspicious that you have hit a limit
- The duration of the outage is determined by the number of files changed since the last backup
- The duration of the outage is only related to the initial cataloguing phase

## SQS

- `Standard Queue`
- Each message will be delivered at least once. This ensures that no message is lost, but leaves you to manage duplicates
- The order that message are processed is loosely sequential, but this cannot be relied on (look for FIFO)
- `DelaySeconds` delays the message to be visible once it's added to the queue
- `visibilityTimeout`
  - The time in which the message becomes hidden while the worker is processing it
  - Increasing the visibility timeout will not decrease cost over time.

## Security

- `SSE-S3` uses managed keys and one of the strongest block ciphers available, AES-256, to secure your data at rest
- `AWS-KMS` provides an audit trail, so you can see who used your key to access which object and when, as well as view failed attempts to access data from users without permission to decrypt the data.

## CloudWatch

- Minimum time interval is `1 minute`
- Stores metrics for terminated Amazon EC2 instances or deleted Elastic Load Balancers for `15 months`

## Trusted Advisor

- Whether there is MFA configured on the root account
- Advice on security groups and what ports have unrestricted access

## Server Migration Service

- Maximum number of volumes that can be attached to a VMs during a SMS migration job is `22`

## Lambda Functions

- Version numbers are never reused, even for a function that has been deleted and recreated
- You can delete a specific Lambda function version only if there are no aliases dependent on this version
- If you don't specify any version in a `DeleteFunction` request, the entire function including all of its versions and aliases will be deleted
- Lambda only publishes a new version if the code hasn't yet been published or if the code has changed when compared against the `$LATEST` version. When you publish additional versions, AWS Lambda assigns a monotonically increasing sequence number for versioning

## Support

### Levels

- Basic
- Developer
- Business
- Enterprise
