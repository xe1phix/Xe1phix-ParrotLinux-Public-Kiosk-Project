DevOps performance: (Elite, High, Medium, Low)
1.	Deployment frequency
2.	Lead time for changes
3.	Time to restore service
4.	Change failure rate

Continuous deployment models:
1.	Blue/Green: Changes are rolled out to green env. Once tested, load balancer is adjusted accordingly.
2.	Canary Releasing: Changes are pushed to one server. Tested. If works, pushed to more servers, and so on.
3.	A/B Testing: Changes are pushed to a segment of the user population.
4.	Dark Launching: Changes are pushed to a newly built parallel production system. Tested. Developers use the practice called: “Branching by abstraction” (hiding features) or ‘feature switches’

Jenkins is not secure by default.

Rapid Risk Assessment during threat modeling (pre-commit security tasks)

Pre-commit git secrets scan and false positive handling:
•	git secrets --install
•	git secrets --register-aws
•	git secrets --scan
•	git secrets --list
•	echo “01234567890123456789” >> .gitallowed

SAST lint checks:
1.	Chef: foodcritic, rubocop
2.	Puppet: puppet parser validate, puppet-lint, puppet-lint security plugins
3.	Ansible: ansible-lint
4.	Cloud Formation: cfn_nag, cfn-python-lint, cfripper
5.	Terraform: terrascan, tflint

Cloud Formation: Parameters, Mappings, Resources, Outputs, etc.
-	Base64, FindInMap, GetAtt, GetAZs, Join, Select, Sub, Ref

# DevSecOps best practices:
•	Threat Modeling -> Tactical Threat Modeling
https://safecode.org/safecodepublications/tactical-threat-modeling/
•	SAST, SCA, DAST full scan -> Incremental scan + automatic false-positives management + parsing scan results to decide pipeline continuity
•	Risk Assessment -> Rapid Risk Assessment
  https://infosec.mozilla.org/guidelines/risk/rapid_risk_assessment.html
•	Transversal Security Requirements verification -> Use of compliance-as-code tools with internal developments
•	Code Reviews --> High-risk code review
•	Vuln fix --> write unit test first, then fix vuln

Declarative: WHAT? Doesn’t care about detailed steps…
Imperative: HOW? More developer friendly, goes into detailed steps…

Puppet Forge  https://forge.puppet.com/    (Server & Agents)  Declarative 
(Code: Package->File->Service) (Resources->Modules->Profiles->Role->Node)
(managing secrets in Yaml file using encrypted Yaml  eyaml file)
(-noop mode is for forensics/detective change control, doesn’t change configuration)

Ansible Galaxy  https://galaxy.ansible.com/home (agentless)  Declarative
Chef Supermarket  https://supermarket.chef.io/ (agent)  Imperative
Salt  Agent or Server or Agent+Server
CFEngine  Promises  Declarative

Docker / container security issues in general:
1.	Ephemeral runtime: difficult to track and manage using classic network defenses (WAF, IDS/IPS)

Docker Bench for security -> tool to scan to verify CIS recommendations being applied or not
Docker Actuary -> Extension to Docker Bench, allows to create custom security scan profiles. All nodes in Swarm can be scanned.

Morgue: Incident Analyzing tool (open source) from Etsy to manage postmortem data	

CIS Controls and DevOps

Peer review process
 
Benefits of containers
Docker commands
  
Azure CLI

# AWS:
VPC – Subnets
	Subnets attached to Internet Gateway, go to internet
 Network ACL (NACL) is stateless but Security Group is stateful.
CloudFormation: Parameters -> Mappings -> Resources -> Outputs
 
Azure Resource Manager provides ability to tag resources.
-	Rollbacks are not supported for nested templates

Terraform provides detailed execution plan before it actually applies the changes:
-	terraform plan
Terraform state file is created locally, by default. Put it centrally (e.g. s3 bucket) for collaboration purpose.
-	Doesn’t support rollback in case of errors
-	“null_resource” for custom resources
-	I/p variables -> Provider -> Resource -> Data source -> Null resource / local provisioner -> Output

AWS KMS
-	Set ORIGIN to EXTERNAL so that KMS will not create key material and expects customer create it (CMK)
-	KMS is multi-tenant whereas CloudHSM is single-tenant

AWS CloudFront Origin Access Identity (OAI) ensures data is provided only when requested from authorized source

AWS Trusted Signer’s key pair for URL and Cookies MUST be created from root account only.
-	Custom policy is better than Canned policy
 

# Blue/Green deployment:
Register green (attach) -> Increase capacity (set-desired-capacity) -> Stop blue (detach) -> Put blue standby (enter-standby)
Also possible to swap TaskDef in ECS for blue/green deployments

Azure WAF  No custom rule support (two modes: Blocking mode or passive monitoring mode)

AWS CloudWatch metrics: High resolution: 1 sec resolution possible
-	VPC flow logs are sent every 10 to 15 min to CloudWatch

AWS CloudTrail: create-subscription -> update-trail -> put-event-selectors
