# ElasticSearch 5.6 Cheatsheet
## Node Decomission
If you need to decomission a node the first thing you should do is transfer all shards from it to other nodes

### Start Moving all Shards off a node
This command will tell ElasticSearch to:
1. Stop sending new shards to node 10.0.0.1
2. Move all existing shards on node 10.0.0.1 to other nodes in the cluster

```
NODE="127.0.0.1"
curl -X PUT "${NODE}:9200/_cluster/settings?pretty" -H 'Content-Type: application/json' -d'
{
  "transient" : {
"cluster.routing.allocation.exclude._ip" : "10.0.0.1"
  }
}
'
```
### Checking how many documents are left on a node
To know if you are done relocating the shard you can run this command to see if there are any documents left

```
curl -XGET 'http://ES_SERVER:9200/_nodes/NODE_NAME/stats/indices?pretty
```


### Cancel Decomission
If you decide you actually want to keep the node run this command.

```
NODE="127.0.0.1"
curl -X PUT "${NODE}:9200/_cluster/settings?pretty" -H 'Content-Type: application/json' -d'
{
  "transient" : {
"cluster.routing.allocation.exclude._ip" : ""
  }
}
'
```


# Snapshots

## Show Indexes in a Snapshot

```
NODE="127.0.0.1"
REPOSITORY="foo"
SNAPSHOT_NAME="bar"
curl -XGET "http://${NODE}:9200/_snapshot/${REPOSITORY}/${SNAPSHOT_NAME}?pretty"

# example to show only indexes that start with "graylog_"
curl -XGET "http://${NODE}:9200/_snapshot/${REPOSITORY}/${SNAPSHOT_NAME}?pretty" | grep "graylog_" | sort -u
```

## List all Snapshots in a Repository

```
NODE="127.0.0.1"
REPOSITORY="foo"
curl -X GET "${NODE}:9200/_snapshot/${REPOSITORY}/_all?pretty" | jq -r '.[] | sort_by(.start_time_in_millis) | .[]  | .snapshot'
```

## Show Progress of RUNNING Snapshot
Use this to see how far along a snapshot is that is currently RUNNING

```
NODE="127.0.0.1"
REPOSITORY="foo"
SNAPSHOT_NAME="bar"
curl -X GET "${NODE}:9200/_snapshot/${REPOSITORY}/${SNAPSHOT_NAME}/_status" | jq '.snapshots[]| .stats,.state,.shards_stats'
```

Example Output:

```
{
  "number_of_files": 12458,
  "processed_files": 12413,
  "total_size_in_bytes": 2320082301006,
  "processed_size_in_bytes": 2125845451207,
  "start_time_in_millis": 1571812199400,
  "time_in_millis": 49711011
}
"STARTED"
{
  "initializing": 347,
  "started": 5,
  "finalizing": 0,
  "done": 5497,
  "failed": 1,
  "total": 5850
}

```

# Repositories

## Create Repoistory

### File System
Create repository on file system *(be sure path exists on all nodes)*

```
curl -XPUT 'http://localhost:9200/_snapshot/elastic_backup' -d '{
  "type": "fs",
  "settings": {
    "location": "/mnt/elastic-backup/elastic_backup",
    "compress": true
  }
}'
```

### S3
Prerequisites:
1. ElasticSearch Plugin installed on every node in the cluster
2. ElasticSearch config file updated with aws key and secret (or use IAM role)
3. Pre-existing s3 bucket

#### S3 Plugin Installation
```
cd /usr/share/elasticsearch/plugins
bin/elasticsearch-plugin install repository-s3
```

#### ElasticSearch Config File Changes for S3 Plugin
Modify /etc/elasticsearch/elasticsearch.yml and append
```
cloud.aws.access_key: YOURAccessKEY
cloud.aws.secret_key: YOURsecret_key!
cloud.aws.region: us-east-1
```

#### Create ElasticSearch Repository for pre-existing s3 bucket
Be sure to replace *foo* and *region* in the json shown below
```
BUCKET_NAME="foo"
NODE="127.0.0.1"
curl -X PUT "${NODE}:9200/_snapshot/${BUCKET_NAME}?pretty" -H 'Content-Type: application/json' -d'
{
  "type": "s3",
  "settings": {
    "bucket": "foo",
    "region": "us-east"
  }
}
'
```

## List snapshot repository names
NODE="127.0.0.1"

```
curl -X GET "${NODE}:9200/_cat/repositories?v"
```
## List info about repository

```
NODE="127.0.0.1"
REPOSITORY="foo"
curl -X GET "${NODE}:9200/_snapshot/${REPOSITORY}"
```

## Verify repository

```
NODE="127.0.0.1"
REPOSITORY="foo"
curl -X POST "${NODE}:9200/_snapshot/${REPOSITORY}/_verify"`
```

# AWS S3

## Total S3 Bucket Size
FYI this will scroll a lot of data on screen.. be patient and wait for end

```
# Required - Input Bucket Name
BUCKET="foo"
aws s3 ls --summarize --human-readable --recursive s3://${BUCKET}
```

# Curator
Curator is a tool that can be used to work with snapshots

## Installing Curator
Instructions to install ElasticSearch Curator

### APT
Instructions if using the repositories:
https://www.elastic.co/guide/en/elasticsearch/client/curator/current/apt-repository.html

To install without adding additional repositories:
```
apt-get install python-pip python-dev build-essential
pip install elasticsearch-curator
```

### Yum
https://www.elastic.co/guide/en/elasticsearch/client/curator/current/yum-repository.html


## Initial Config
You need to create this file:
```
~/.curator/curator.yml
```

File Content:
*replace the host names with your host names*
```
# Remember, leave a key empty if there is no value.  None will be a string,
# not a Python "NoneType"
client:
  hosts: [ "mynode1", "mynode2", "mynode3", "mynode4", "mynode5" ]
  port: 9200
  url_prefix:
  use_ssl: False
  certificate:
  client_cert:
  client_key:
  ssl_no_validate: False
  http_auth:
  timeout: 30
  master_only: False

logging:
  loglevel: DEBUG
  logfile: '/root/.curator/curator.log'
  logformat: default
  blacklist: ['elasticsearch', 'urllib3']
```

## Curator CLI
The cli comes along with the regular curator installation

### Show all Snapshots for a repository
```
REPOSITORY="foo"
curator_cli show_snapshots --repository ${REPOSITORY}
```

### Show all indicies
```
curator_cli show_indices
```
