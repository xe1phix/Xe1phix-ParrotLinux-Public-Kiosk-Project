------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#CIS_Kubernetes_V1.20_Benchmark_v1.0.0_PDF

#1.1.1 Ensure that the API server pod specification file permissions are set to 644 or more restrictive
Audit:
controlplane $ stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml
600
controlplane $ ls -lai /etc/kubernetes/manifests/kube-apiserver.yaml
788143 -rw------- 1 root root 3219 Feb  3 06:52 /etc/kubernetes/manifests/kube-apiserver.yaml

Remediation:
chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml

Auditd:
auditctl -w /etc/kubernetes/manifests/kube-apiserver.yaml -p wra -k kube-apiserver-yml
auditctl -l #list labels
stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml # 600
chmod 644 /etc/kubernetes/manifests/kube-apiserver.yaml # trigger
ausearch -k kube-apiserver-yml #audit logs

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
A simple, interactive and fun playground to learn Kubernetes
https://labs.play-with-k8s.com/
Kubernetes Playground
https://www.katacoda.com/courses/kubernetes/playground
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
curl, through a pod inside the cluster and use the ClusterIP address instead of the external IP

# Create a pod inside the cluster with curl
kubectl run --generator=run-pod/v1 curl-$RANDOM --image=radial/busyboxplus:curl -i --tty --rm

# Inside the cluster run curl
$ curl http://x.x.x.x -H "Host: test-go.default.mydomain.com" -v
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#selinux

kubectl -n psp-example create -f- <<EOF
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  privileged: false  # Don't allow privileged pods!
  # The rest fills in some required fields.
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'
EOF

kubectl --as=system:serviceaccount:psp-example:fake-user -n psp-example create -f- <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: pause
spec:
  containers:
    - name: pause
      image: k8s.gcr.io/pause
EOF
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# verify AppArmor support on nodes by checking the node ready condition message
kubectl get nodes -o=jsonpath=$'{range .items[*]}{@.metadata.name}: {.status.conditions[?(@.reason=="KubeletReady")].message}\n{end}'

# view which profiles are loaded on a node
ssh gke-test-default-pool-239f5d02-gyn2 "sudo cat /sys/kernel/security/apparmor/profiles | sort"
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Create multiple YAML objects from stdin
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: busybox-sleep
spec:
  containers:
  - name: busybox
    image: busybox
    args:
    - sleep
    - "1000000"
---
apiVersion: v1
kind: Pod
metadata:
  name: busybox-sleep-less
spec:
  containers:
  - name: busybox
    image: busybox
    args:
    - sleep
    - "1000"
EOF

# Create a secret with several keys
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  password: $(echo -n "s33msi4" | base64 -w0)
  username: $(echo -n "jane" | base64 -w0)
EOF
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
METHOD1 via script

export MINIKUBE_VERSION="1.8.1"
export KUBECTL_VERSION="1.18.1"
export HELM_VERSION="2.16.9"


curl -Lo minikube https://storage.googleapis.com/minikube/releases/v$MINIKUBE_VERSION/minikube-linux-amd64 && chmod +x minikube && sudo mv minikube /usr/local/bin/ # Download minikube
minikube version
curl -Lo kubectl https://storage.googleapis.com/kubernetes-release/release/v$KUBECTL_VERSION/bin/linux/amd64/kubectl && chmod +x kubectl && sudo mv kubectl /usr/local/bin/ # Download kubectl
kubectl version --client
wget -nv https://get.helm.sh/helm-v$HELM_VERSION-linux-amd64.tar.gz && tar xvzf helm-v$HELM_VERSION-linux-amd64.tar.gz && mv linux-amd64/helm linux-amd64/tiller /usr/local/bin
helm version

LATEST VERSIONS
curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 && chmod +x minikube && sudo mv minikube /usr/local/bin/
curl -LO https://storage.googleapis.com/kubernetes-release/release/`curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt`/bin/linux/amd64/kubectl && chmod +x kubectl && sudo mv kubectl /usr/local/bin/
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 && chmod 700 get_helm.sh && bash get_helm.sh


METHOD2 via snap
sudo apt install snapd -y && sudo snap install helm --classic
sudo apt install snapd -y && sudo snap install kubectl --classic
sudo apt install snapd -y && sudo snap install minikube --classic
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
echo echo "Waiting for kubeflowto be ready ..."
for i in {1..60}; do # Timeout after 5 minutes, 60x5=300 secs
      # if kubectl get pods --namespace=kubeflow -l openebs.io/component-name=centraldashboard | grep Running ; then
      if kubectl get pods --namespace=kubeflow  | grep ContainerCreating ; then
        sleep 10
      else
        break
      fi
done
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#check node capacities with the kubectl get nodes -o <format>
#if all nodes have a capacity of cpu:1, then a pod with a request of cpu: 1.1 will never be scheduled.Check that the pod is not larger than nodes

kubectl get nodes -o yaml | egrep '\sname:|cpu:|memory:'
kubectl get nodes -o json | jq '.items[] | {name: .metadata.name, cap: .status.capacity}'
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
kubectl component-status
          # openesb component list
          #https://github.com/openebs/openebs/blob/master/k8s/openebs-operator.yaml
          
          - |
            echo "Waiting for openebs-ndm-operator component to be ready ..."
            for i in {1..60}; do # Timeout after 5 minutes, 150x5=300 secs
                if sudo kubectl get pods --namespace=openebs -l openebs.io/component-name=openebs-ndm-operator | grep Running ; then
                  break
                fi
                sleep 5
            done

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#https://kubernetes.io/docs/reference/kubectl/jsonpath/

$ kubectl get pods --all-namespaces -o=jsonpath='{range .items[*]}{.metadata.name}{"\n"}'
$ kubectl get pods --all-namespaces -o=jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.startTime}{"\n"}{end}'
kubectl get pods --all-namespaces --sort-by='.metadata.creationTimestamp' -o jsonpath='{range .items[*]}{.metadata.name}, {.metadata.creationTimestamp}{"\n"}{end}' #Filter Kubernetes pods by time
#Find Kubernetes Pod by Label Selector and Fetch the Pod Logs
ns='<your-namespace>' label='<yourkey>=<yourvalue>' kubectl get pods -n $ns -l $label -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | xargs -I {} kubectl -n $ns logs {}
#Find a Kubernetes pod by label selector and port-forward locally
ns='<your-namespace>' label='<yourkey>=<yourvalue>' kubectl -n $ns get pod -l $label -o jsonpath='{.items[1].metadata.name}' | xargs -I{} kubectl -n $ns port-forward {} 8080:80
#Get the external IP for Kubernetes nodes
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name} {.status.addresses[?(@.type=="ExternalIP")].address}{"\n"}{end}'
#List all Container images in all namespaces 
kubectl get pods --all-namespaces -o jsonpath="{.items[*].spec.containers[*].image}" |\
tr -s '[[:space:]]' '\n' |\
sort |\

#List Container images by Pod
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{"\n"}{.metadata.name}{":\t"}{range .spec.containers[*]}{.image}{", "}{end}{end}' |\
#List Container images filtering by Pod label
kubectl get pods --namespace kube-system -o jsonpath="{.items[*].spec.containers[*].image}"
sort
uniq -c
#List Container images using a go-template instead of jsonpath
kubectl get pods --all-namespaces -o go-template --template="{{range .items}}{{range .spec.containers}}{{.image}} {{end}}{{end}}"
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
kubectl get pods --all-namespaces -o json #see all the data  to filter on for the 'Filter Kubernetes pods by time' 
kubectl get pods --all-namespaces -o json | jq '.items[] | .spec.nodeName' -r | sort | uniq -c #Count the number of pods on a Kubernetes node
#Get a list of pods for each node
kubectl get pods --all-namespaces -o json | jq '.items | map({podName: .metadata.name, nodeName: .spec.nodeName}) | group_by(.nodeName) | map({nodeName: .[0].nodeName, pods: map(.podName)})'
kubectl explain deployment.spec.selector #more info on selectors

kubectl get nodes -l 'master' or kubectl get nodes -l '!master' #Filter nodes by label

#Postman to explore Kubernetes API.
curl -s http://localhost:8000/api/v1/nodes | jq '.items[] .metadata.labels' #The equivalent curl command to get all the nodes
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#parse JSON format output  using jq and create an array
kubectl get pods -o json | jq '.items[].spec.containers[].env'

############bashscript############
#!/bin/bash

NAMES=`kubectl get pods -o=jsonpath='{range .items[*]}{.spec.containers[*].env[*].name}{"\n"}' | tr -d '\011\012\015'`
VALUES=`kubectl get pods -o=jsonpath='{range .items[*]}{.spec.containers[*].env[*].value}{"\n"}' | tr -d '\011\012\015'`

IFS=' ' read -ra NAMESA <<< "$NAMES"
IFS=' ' read -ra VALUESA <<< "$VALUES"

MAXINDEX=`expr ${#NAMESA[@]} - 1`

printf "[\n"
for i in "${!NAMESA[@]}"; do
  printf "  {\n"
  printf "  \"USER_NAME\": \"${NAMESA[$i]}\",\n"
  printf "  \"USER_ADDRESS\": \"${VALUESA[$i]}\"\n"
  if [ "$i" == "${MAXINDEX}" ]; then
    printf "  }\n"
  else
    printf "  },\n"
  fi
done
printf "]\n"
############bashscript############
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Docker Desktop win/mac

#Kubernetes dashboard
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.0-rc5/aio/deploy/recommended.yaml
OR
kubectl create -f kubernetes-dashboard.yaml
kubectl get pod -n kubernetes-dashboard
kubectl proxy &
http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/

kubectl proxy --port=8000 #Through this proxy session, any request sent to localhost:8000 will be forwarded to the Kubernetes API server

#Mac
TOKEN=$(kubectl -n kube-system describe secret default| awk '$1=="token:"{print $2}')
kubectl config set-credentials docker-for-desktop --token="${TOKEN}"
echo $TOKEN
#Win
$TOKEN=((kubectl -n kube-system describe secret default | Select-String "token:") -split " +")[1]
kubectl config set-credentials docker-for-desktop --token="${TOKEN}"
echo $TOKEN

Mac: $HOME/.kube/config
Win: %UserProfile%\.kube\config

Ingress
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-0.32.0/deploy/static/provider/cloud/deploy.yaml
kubectl get pods --all-namespaces -l app.kubernetes.io/name=ingress-nginx

#Test Application
kubectl create -f sample/apple.yaml
kubectl create -f sample/banana.yaml
kubectl create -f sample/ingress.yaml

$ curl -kL http://localhost/apple
apple
$ curl -kL http://localhost/banana
banana


kubectl delete -f sample/apple.yaml
kubectl delete -f sample/banana.yaml
kubectl delete -f sample/ingress.yaml
kubectl delete -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-0.32.0/deploy/static/provider/cloud/deploy.yaml

Mac: 
brew install helm
helm repo add stable http://mirror.azure.cn/kubernetes/charts/
helm repo update
Win: 
choco install kubernetes-helm
helm repo add stable http://mirror.azure.cn/kubernetes/charts/
helm repo update

Test application
helm install wordpress stable/wordpress
helm status wordpress
helm uninstall wordpress


kubectl -n kube-system get pods -l app=helm # Check whether the helm tiller pod is running
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
watch microk8s.kubectl get all --all-namespaces #check deployment progress
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
          - sudo apt-get install net-tools -qqy #Install netcat
          - kubectl proxy & # Access Dashboard using the kubectl command-line tool by running the following command, Starting to serve on 127.0.0.1:8001
          - |
            for i in {1..60}; do # Timeout after 5 minutes, 60x1=60 secs
              if nc -z -v 127.0.0.1 8001 2>&1 | grep succeeded ; then
                break
              fi
              sleep 1
            done
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------          
        - |
          echo "Waiting for Kubernetes to be ready ..."
          for i in {1..150}; do # Timeout after 5 minutes, 150x2=300 secs
              if sudo microk8s kubectl get pods --namespace=kube-system | grep Running ; then
                break
              fi
              sleep 2
          done
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------          
          - echo "=========================================================================================="
          - echo "=============================Inspection============================================================="
          - echo "=========================================================================================="
          - kubectl get pod -o wide #The IP column will contain the internal cluster IP address for each pod.
          - kubectl get service --all-namespaces # find a Service IP,list all services in all namespaces
          - docker ps #Find the container ID or name of any container in the pod
          # - docker inspect --format '{{ .State.Pid }}' container-id-or-name #get the process ID of either container, take note of the container ID or name
          # - nsenter -t your-container-pid -n ip addr #advantage of using nsenter to run commands in a pod’s namespace – versus using something like docker exec – is that you have access to all of the commands available on the node
          # - nsenter -t your-container-pid -n ip addr #Finding a Pod’s Virtual Ethernet Interface
          # - curl $CONTAINERIP:8080 #confirm that the web server is still running on port 8080 on the container and accessible from the node
          - echo "=============================Inspecting Conntrack Connection Tracking============================================================="
          # - sudo apt-get -qq -y install conntrack #http://conntrack-tools.netfilter.org/
          - sudo apt-get -qq -y install bridge-utils # Install Linux Bridge Tools.
          - sudo apt-get -qq -y install tcpdump
          - sudo ip address show #List your networking devices
          - sudo ip netns list # list configured network namespaces
          - sudo ip netns add demo-ns #add a namespace called demo-ns
          - sudo ip netns list #see that it's in the list of available namespaces
          #A network namespace is a segregated network environment, complete with its own network stack
          - sudo ip netns exec demo-ns bash #start bash in our new namespace and look for interfaces that it knows about
          - sudo ip netns exec demo-ns bash
          - ping 8.8.8.8 #ping Google's public DNS server
          #Observe that we have no route out of the namespace, so we don't know how to get to 8.8.8.8 from here
          - netstat -rn #Check the routes that this namespace knows about
          # - sudo tcpdump -ni veth0  icmp -c 4 #Confirm that the ping is still running and that both veth0 and cbr0 can see the ICMP packets in the default namespace
          # - sudo tcpdump -ni eth0  icmp -c 4 #Now check whether eth0 can see the ICMP packets
          # - sudo sysctl net.ipv4.conf.all.forwarding=1 #Turn forwarding on,Linux, by default, doesn't forward packets between interfaces
          # - sudo tcpdump -ni eth0  icmp -c 4 #run tcpdump against eth0 to see if fw is working
          # - sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE #make all outgoing packets from the host look like they're coming from the host's eth0 IP address
          # - sudo tcpdump -ni eth0  icmp # sniff
          # - sudo conntrack -L |grep 8.8.8.8 #iptables applies new rules to new flows and leaves ongoing flows alone
          - ip address show
          - ip route show
          - sudo arp #Let's understand how the connectivity looks from the namespace's layer 2 perspective. Confirm that, from demo-ns, the MAC address of192.168.255.1
          - ping 192.168.255.1 #Attempt to to ping cbr0,From this namespace, we can only see a local loopback interface. We can no longer see or ping eth0 or cbr0.
          - exit #Exit out of the demo-ns namespace
          - ip address show #Confirm that you can see the interfaces in the default namespace
          - sudo arp #Confirm that you can see the interfaces in the default namespace
          - sudo tcpdump -ni eth0 icmp -c 4 #Confirm that you can see the interfaces in the default namespace
          - sudo conntrack -L | grep 8.8.8.8
          - conntrack -L #list all the connections currently being tracked
          - conntrack -E && sleep 5 #watch continuously for new connections
          # - conntrack -L -f ipv4 -d IPADDRESS -o extended #grep conntrack table information using the source IP and Port
          # - kubectl get po — all-namespaces -o wide | grep IPADDRESS #use kubectl to lookup the name of the pod using that Pod IP address
          # - conntrack -D -p tcp --orig-port-dst 80 # delete the relevant conntrack state
          # - sudo conntrack -D -s IPADDRESS
          # - conntrack -L -d IPADDRESS #list conntrack-tracked connections to a particular destination address
          - echo "=============================Inspecting Iptables Rules============================================================="
          - sysctl net.netfilter.nf_conntrack_max #sysctl setting for the maximum number of connections to track
          - sudo sysctl -w net.netfilter.nf_conntrack_max=191000 #set a new valu
          - sudo iptables-save | ead -n 20 #dump all iptables rules on a node
          - iptables -t nat -L KUBE-SERVICES #list just the Kubernetes Service NAT rules
          - echo "=============================Querying Cluster DNS============================================================="
          - sudo apt install dnsutils -y #if dig is not installed
          - kubectl get service -n kube-system kube-dns #find the cluster IP of the kube-dns service CLUSTER-IP
          # - nsenter -t 14346 -n dig kubernetes.default.svc.cluster.local @IPADDRESS #nsenter to run dig in the a container namespace, Service’s full domain name of service-name.namespace.svc.cluster.local
          - ipvsadm -Ln #list the translation table of IPs ,kube-proxy can configure IPVS to handle the translation of virtual Service IPs to pod IPs
          # - ipvsadm -Ln -t IPADDRESS:PORT #show a single Service IP
          - echo "=========================================================================================="
------------------------------------------------------------------------------------------------
kubectl get pod -o wide #The IP column will contain the internal cluster IP address for each pod.
------------------------------------------------------------------------------------------------
problem:
TASK [Initialize the cluster] ***************************************************************************************************************************************************************
fatal: [k8s-master01]: FAILED! => {"changed": true, "cmd": "kubeadm init --apiserver-advertise-address=\"10.217.50.10\" --apiserver-cert-extra-sans=\"10.217.50.10\"  --node-name k8s-master01 --pod-network-cidr=10.217.0.0/16 >> cluster_initialized.txt", "delta": "0:01:53.833753", "end": "2020-01-27 11:50:37.254008", "msg": "non-zero return code", "rc": 1, "start": "2020-01-27 11:48:43.420255", "stderr": "I0127 11:48:44.476999   29137 version.go:248] remote version is much newer: v1.17.2; falling back to: stable-1.15\nerror execution phase preflight: [preflight] Some fatal errors occurred:\n\t[ERROR ImagePull]: failed to pull image k8s.gcr.io/kube-proxy:v1.15.9: output: Error response from daemon: Get https://k8s.gcr.io/v2/: net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)\n, error: exit status 1\n[preflight] If you know what you are doing, you can make a check non-fatal with `--ignore-preflight-errors=...`", "stderr_lines": ["I0127 11:48:44.476999   29137 version.go:248] remote version is much newer: v1.17.2; falling back to: stable-1.15", "error execution phase preflight: [preflight] Some fatal errors occurred:", "\t[ERROR ImagePull]: failed to pull image k8s.gcr.io/kube-proxy:v1.15.9: output: Error response from daemon: Get https://k8s.gcr.io/v2/: net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)", ", error: exit status 1", "[preflight] If you know what you are doing, you can make a check non-fatal with `--ignore-preflight-errors=...`"], "stdout": "", "stdout_lines": []}

test:
vagrant@k8s-master01:~$ docker pull k8s.gcr.io/kube-proxy:v1.15.9
v1.15.9: Pulling from kube-proxy
39fafc05754f: Already exists                                                                                                                                                                 db3f71d0eb90: Pull complete                                                                                                                                                                  ae50d9363009: Pull complete                                                                                                                                                                  Digest: sha256:fd8bfaceacce72ce1c1829941d0df50860f28d7f60b4b41b1b849cc73a4d1316
Status: Downloaded newer image for k8s.gcr.io/kube-proxy:v1.15.9

------------------------------------------------------------------------------------------------
kubectl create -f /vagrant/app/jenkins/1/jenkins-deployment.yaml
service/jenkins-svc created
error: unable to recognize "/vagrant/app/jenkins/1/jenkins-deployment.yaml": no matches for kind "Deployment" in version "extensions/v1beta1"

#check what api supports current Kubernetes
kubectl api-resources | grep deployment
deployments                       deploy       apps                           true         Deployment

sed -i 's|extensions/v1beta1|apps/v1|g' /vagrant/app/jenkins/1/jenkins-deployment.yaml
------------------------------------------------------------------------------------------------
# deploy hello-minikube on any k8s NOT MINIKUBE environment
kubectl run hello-minikube --image=k8s.gcr.io/echoserver:1.10 --port=8080
kubectl expose deployment hello-minikube --type=NodePort
kubectl get pod -n default -o wide  --all-namespaces
kubectl -n default get services
curl http://worker02:31868/
------------------------------------------------------------------------------------------------ 
[preflight] Running pre-flight checks
[WARNING SystemVerification]: this Docker version is not on the list of validated versions: 18.09.8. Latest validated version: 18.06
the docker-ce-cli package was introduced in Docker CE 18.09.

#Swap must be disabled
cat /proc/swaps -> check if swap is enabled 
swapoff -> turn it off
/etc/fstab -> make permanent by commenting out the swap file

ifconfig -> find private/public/datacenter IP address

--apiserver-advertise-address -> determines which IP address Kubernetes should advertise its API server on
                                 use the internal IP address to broadcast the Kubernetes API — rather than the Internet-facing address
 --pod-network-cidr ->needed for the flannel driver and specifies an address space for containers
 --skip-preflight-checks ->allows kubeadm to check the host kernel for required features. 
 
 sudo cat /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
 ------------------------------------------------------------------------------------------------
 kubectl get pods->View the Pod
 kubectl get deployments->View the Deployment
 kubectl get events
 kubectl get events -n <namespace>
 kubectl config view
 kubectl cluster-info
 kubectl cluster-info dump #debug and diagnose cluster problems
------------------------------------------------------------------------------------------------ 
 kubectl config use-context minikube
 "kubectl label node <nodename> <labelname>-"  ->delete labels from its respecitve nodes
 kubectl -n ceph get pods
 kubectl -n kube-system get svc/kube-dns-> get the IP address of the kube-dns service
 kubectl get secrets -n ceph

 helm del --purge ceph
 helm init
 helm serve &
 helm repo add local http://localhost:8879/charts
 
 ------------------------------------------------ ------------------------------------------------
sudo kubectl run --image=nginx nginx-app --port=80 --env="DOMAIN=cluster"
sudo kubectl expose deployment nginx-app --port=80 --name=nginx-http
sudo docker ps -a

#Create the namespace
kubectl create namespace sock-shop
#Create the actual Sock Shop application
kubectl apply -n sock-shop -f "https://github.com/microservices-demo/microservices-demo/blob/master/deploy/kubernetes/complete-demo.yaml?raw=true"
#interact with it via the front-end service
kubectl -n sock-shop get svc front-end
#browse
Visit http://<cluster-ip> (in this case, http://10.110.250.153) 

Deploying and Accessing an Application
kubectl run --image=nginx:latest myweb

kubectl get pods
kubectl delete pods echo-example
kubectl delete pod,service echo-example
kubectl delete pod xxx --now

kubectl get services
kubectl delete service echo-example

kubectl expose pod myweb-59d7488cb9-jvnwn --port=80 --target-port=80 --type=NodePort
#get the NodePort of the myweb deployment
kubectl get svc myweb-59d7488cb9-jvnwn
#Use the curl command to make an HTTP request to one of the nodes on port 31930.
curl http://your_worker_1_ip_address:31930/

sudo kube-apiserver --version
sudo kube-controller-manager  --version
sudo kube-scheduler --version
sudo etcd --version

undo what kubeadm did, you should first drain the node and make sure that the node is empty before shutting it down.
kubectl drain <node name> --delete-local-data --force --ignore-daemonsets
kubectl delete node <node name>
kubeadm reset
iptables -F && iptables -t nat -F && iptables -t mangle -F && iptables -X

$ kubeadm token list

------------------------------------------------------------------------------------------------
deploy
export VAL=$(sudo kubectl version | base64 | tr -d '\n')
kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$VAL"
remove 
$ kubectl delete -f "https://cloud.weave.works/k8s/net?k8s-version=$VAL"

deploy
$ sudo kubectl apply -f https://git.io/weave-kube-1.6
remove 
$ sudo kubectl -n kube-system delete -f https://git.io/weave-kube-1.6

$ sudo kubectl get pods -n kube-system -l name=weave-net
$ sudo kubectl get pods -n kube-system -o wide | grep weave-net
$ kubectl get pods --all-namespaces | grep weave
$ kubectl run --image=weaveworks/hello-world hello

kubectl get pod <pod name> -n <namespace name> -o yaml #see all the information of a particular pod

$ kubectl describe pod weave-net-6gv8p -n kube-system
$ sudo kubectl logs weave-net-6gv8p weave -n kube-system --previous
$ kubectl get nodes -o jsonpath='{.items[*].spec.podCIDR}'
$ sudo kubectl get pods -n kube-system -o wide | grep weave-net
$ sudo kubectl get pods -n kube-system -l name=weave-net -o wide
$ sudo kubectl logs -n kube-system weave-net-t5gcr weave | tail -n 5
$ sudo kubectl --namespace kube-system get ds weave-net

------------------------------------------------------------------------------------------------
$ kubectl get deployments
NAME    READY   UP-TO-DATE   AVAILABLE   AGE
hello   1/1     1            1           73m

$ sudo kubectl -n kube-system get deployments

find the cluster IP address of a Kubernetes pod.The IP column will contain the internal cluster IP address for each pod.
$ kubectl --kubeconfig ./admin.conf get pod -o wide
NAME                     READY   STATUS    RESTARTS   AGE     IP          NODE       NOMINATED NODE   READINESS GATES
hello-569997c54c-gpw8q   1/1     Running   0          8m41s   10.32.0.2   worker01   <none>           <none>

list all pods in all namespaces by adding the flag --all-namespaces
$ kubectl get pod -n default -o wide  --all-namespaces
NAMESPACE     NAME                                   READY   STATUS    RESTARTS   AGE    IP              NODE           NOMINATED NODE   READINESS GATES
default       hello-569997c54c-gpw8q                 1/1     Running   0          42m    10.32.0.2       worker01       <none>           <none>


get the IP address of the kubernetes service in default namespace(ns)
$ kubectl -n default get svc/kubernetes
NAME         TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
kubernetes   ClusterIP   10.96.0.1    <none>        443/TCP   117m

list secrets in default namespace(ns)
$ kubectl get secrets -n default
NAME                  TYPE                                  DATA   AGE
default-token-mxdpm   kubernetes.io/service-account-token   3      114m


list services in default namespace(ns)
$ kubectl -n default get services
NAME         TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
kubernetes   ClusterIP   10.96.0.1    <none>        443/TCP   113m

list pods in default namespace(ns) 
$  kubectl -n default get pods
NAME                     READY   STATUS    RESTARTS   AGE
hello-569997c54c-gpw8q   1/1     Running   0          50m

list all services in all namespaces.The service IP can be found in the CLUSTER-IP column
$ kubectl get service --all-namespaces
NAMESPACE     NAME         TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)                  AGE
default       kubernetes   ClusterIP   10.96.0.1    <none>        443/TCP                  103m
kube-system   kube-dns     ClusterIP   10.96.0.10   <none>        53/UDP,53/TCP,9153/TCP   103m

#list all the containers in a pod
kubectl get pods POD_NAME_HERE -o jsonpath='{.spec.containers[*].name}'
kubectl get pods POD_NAME_HERE -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}'
kubectl get pods -o=custom-columns=PodName:.metadata.name,Containers:.spec.containers[*].name,Image:.spec.containers[*].image
kubectl get pods  -o=jsonpath='{range .items[*]}{"\n"}{.metadata.name}{":\t"}{range .spec.containers[*]}{.image}{end}{end}' && printf '\n'
kubectl get po -o jsonpath='{range .items[*]}{"pod: "}{.metadata.name}{"\n"}{range .spec.containers[*]}{"\tname: "}{.name}{"\n\timage: "}{.image}{"\n"}{end}'

#list both init and non-init containers for all pods
kubectl get pod -o="custom-columns=NAME:.metadata.name,INIT-CONTAINERS:.spec.initContainers[*].name,CONTAINERS:.spec.containers[*].name

#details of a pod
kubectl get --all-namespaces --selector k8s-app=kube-dns --output json pods \
  | jq --raw-output '.items[].spec.containers[].name'
#details of one specific container 
kubectl get --all-namespaces --selector k8s-app=kube-dns --output json pods \
  | jq '.items[].spec.containers[] | select(.name=="etcd") 
------------------------------------------------------------------------------------------------
#troubleshooting Kubernetes, debugging Pending Pods
kubectl get pods
kubectl describe pod [name]
kubectl get pod [name] -o yaml
kubectl get events
kubectl get events --namespace=my-namespace
kubectl get events --all-namespaces
kubectl logs ${POD_NAME} ${CONTAINER_NAME} #the logs of the affected container
kubectl logs --previous ${POD_NAME} ${CONTAINER_NAME} #access the previous container's crash log
------------------------------------------------------------------------------------------------
#troubleshooting Kubernetes, Debugging with container exec
kubectl exec ${POD_NAME} -c ${CONTAINER_NAME} -- ${CMD} ${ARG1} ${ARG2} ... ${ARGN}
#-c ${CONTAINER_NAME} is optional. You can omit it for Pods that only contain a single container.
kubectl exec cassandra -- cat /var/log/cassandra/system.log
kubectl exec -it cassandra -- sh
------------------------------------------------------------------------------------------------
#troubleshooting Kubernetes, debugging using ephemeral containers

kubectl run ephemeral-demo --image=registry.k8s.io/pause:3.1 --restart=Never #create a pod
kubectl exec -it ephemeral-demo -- sh #see an error because there is no shell in this container image

# instead add a debugging container
#utomatically attach to the console of the Ephemeral Container.
#--target parameter targets the process namespace of another container
kubectl debug -it ephemeral-demo --image=busybox:1.28 --target=ephemeral-demo 
kubectl describe pod ephemeral-demo
------------------------------------------------------------------------------------------------
#troubleshooting Kubernetes, Debugging using a copy of the Pod
#can't run kubectl exec to troubleshoot your container if your container image does not include a shell
#if your application crashes on startup
#use kubectl debug to create a copy of the Pod with configuration values changed to aid debugging

#application's container images are built on busybox but debugging utilities not included in busybox
kubectl run myapp --image=busybox:1.28 --restart=Never -- sleep 1d
#create a copy of myapp named myapp-debug that adds a new Ubuntu container for debugging
#kubectl debug automatically generates a container name if you don't choose one using the --container flag
kubectl debug myapp -it --image=ubuntu --share-processes --copy-to=myapp-debug
# clean up the debugging Pod
kubectl delete pod myapp myapp-debug
------------------------------------------------------------------------------------------------
#troubleshooting Kubernetes,Copying a Pod while changing container images

kubectl run myapp --image=busybox:1.28 --restart=Never -- sleep 1d # create a Pod
kubectl debug myapp --copy-to=myapp-debug --set-image=*=ubuntu #make a copy and change its container image to ubuntu

------------------------------------------------------------------------------------------------
#troubleshooting Kubernetes,Debugging via a shell on the nod

# find the Node on which the Pod is running
#create a Pod running on the Node
#create an interactive shell on a Node
kubectl debug node/mynode -it --image=ubuntu
------------------------------------------------------------------------------------------------
#troubleshooting Kubernetes, Copying a Pod while changing its command

#simulate a crashing application
kubectl run --image=busybox:1.28 myapp -- false
#container is crashing: CrashLoopBackOff
kubectl describe pod myapp 
#create a copy of this Pod with the command changed to an interactive shell:
kubectl debug myapp -it --copy-to=myapp-debug --container=myapp -- sh
# clean up the debugging Pod
kubectl delete pod myapp myapp-debug
------------------------------------------------------------------------------------------------
#troubleshooting Kubernetes, Node Not Ready
kubectl get pods
kubectl delete node [name] #Remove failed node from the cluster
kubectl delete pods [pod_name] --grace-period=0 --force -n [namespace] #Delete stateful pods with status unknown
------------------------------------------------------------------------------------------------
#troubleshooting CrashLoopBackOff,Insufficient resources/Volume mounting/Use of hostPort
kubectl get pods
kubectl describe pod [pod_name]
------------------------------------------------------------------------------------------------
#ImagePullBackOff or ErrImagePull,Wrong image name or tag / Authentication issue in Container registry
kubectl get pods
kubectl describe pod [pod_name]
------------------------------------------------------------------------------------------------
#troubleshooting CreateContainerConfigError
kubectl get pods #identify the issue
kubectl describe pod pod-missing-config  #Getting detailed information
kubectl get configmap configmap-3 #see if the ConfigMap exists in the cluster.

------------------------------------------------------------------------------------------------
#troubleshooting

kubectl apply -f https://gist.githubusercontent.com/omerlh/cc5724ffeea17917eb06843dbff987b7/raw/1e58c8850aeeb6d22d8061338f09e5e1534ab638/daemonset.yaml
kubectl get pods -l app=disk-checker
kubectl logs -l app=disk-checker
------------------------------------------------------------------------------------------------
#troubleshooting

systemctl status kubelet#SSH	to	the	worker	nodes To	check	to	see	if	the	Kubelet	Service	is	running
ps -ef | grep kubelet #
systemctl cat kubelet.service
 
 $ ss -tlpn | grep LISTEN | grep 'kube-proxy\|kubelet\|kube-scheduler\|kube-apiserver\|etcd\|kube-controller\|haproxy'
 
docker ps -a | grep kube | grep -v pause
docker logs CONTAINERID
  
sudo docker info |grep -i cgroup

journalctl -ul docker
sudo journalctl -u kubelet.service -n 20
sudo journalctl -u etcd.service
sudo journalctl -u kube-apiserver.service
sudo journalctl -u kube-controller-manager.service
sudo journalctl -u kube-scheduler.service
sudo journalctl -u kubelet.service
sudo journalctl -u kube-proxy.service
sudo journalctl -u docker.service
sudo journalctl -xn --unit kubelet.service

kubectl get endpoints
kubectl get pods -n kube-system
kubectl get services -n kube-system
kubectl get deployments
kubectl get rs
kubectl -n default get rs
kubectl get svc

$ kubectl -n kube-system edit configmap kubeadm-config
$ kubectl get ep

List all of the ingresses
$ kubectl get ingress
$ kubectl describe ingress web

$ kubectl get pods
$ kubectl exec nginx-ingress-1167843297-40nbm -it bash

$ kubectl get pods -o wide
$ kubectl -n kube-system get pods --watch
$ kubectl logs web-2136164036-ghs1p
$ kubectl logs -n default web-2136164036-ghs1p
$ kubectl -n kube-system logs etcd-operator-86ccfd897-f5b59

external load balancer-LoadBalancer Ingress:
$ kubectl get services
$ kubectl describe service ingress-lb
$ curl -H "HOST: www.example.com"
$ nslookup www.example.com

look at the logs from a running Cassandra pod
kubectl exec cassandra -- cat /var/log/cassandra/system.log

kubectl exec -ti POD-UID nslookup SERVICE-NAME
kubectl exec -ti POD-UID -- /bin/bash

$ kubectl get namespaces
NAME              STATUS   AGE
default           Active   19m
kube-node-lease   Active   19m
kube-public       Active   19m
kube-system       Active   19m
$ kubectl -n kube-system get pods
NAME                                   READY   STATUS             RESTARTS   AGE
cilium-9bd84                           0/1     CrashLoopBackOff   7          16m
$ kubectl -n kube-system describe pod cilium-9bd84

" Warning  FailedScheduling  30s (x3 over 99s)  default-scheduler  0/3 nodes are available: 3 node(s) had taints that the pod didn't tolerate"
$ kubectl taint nodes worker02 key=value:NoSchedule
node/worker02 tainted

$ kubectl -n kube-system get pods --selector=k8s-app=cilium
NAME           READY   STATUS             RESTARTS   AGE
cilium-9bd84   0/1     CrashLoopBackOff   9          26m
cilium-dqc6v   0/1     CrashLoopBackOff   6          27m
cilium-m2crc   0/1     CrashLoopBackOff   9          26m

$ kubectl -n kube-system logs cilium-9mj7q
level=fatal msg="kernel version: NOT OK: minimal supported kernel version is >= 4.8.0; kernel version that is running is: 4.4.0" subsys=daemon
------------------------------------------------------------------------------------------------
# reset and rejoin master
sudo kubeadm reset
sudo kubeadm init --apiserver-advertise-address="10.217.50.10" --apiserver-cert-extra-sans="10.217.50.10"  --node-name k8s-master01 --pod-network-cidr=10.217.0.0/16 
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/v1.5/examples/kubernetes/1.14/cilium.yaml
kubeadm token create --print-join-command >> join_command

$ sudo kubectl --kubeconfig /etc/kubernetes/admin.conf get nodes

# reset and rejoin worker
sudo kubeadm reset
(join_command - master)
sudo kubeadm join 10.217.50.10:6443 --token qwoqw8.s1u6aza3gafmz2qk     --discovery-token-ca-cert-hash sha256:473c8e65cc39386efdd611f770e2801c58ac96086f40dc4f28e7083d89bddd2f

------------------------------------------------------------------------------------------------
# cilium pod network

In order for the TLS certificates between etcd peers to work correctly, a DNS reverse lookup on a pod IP must map back to pod name
check the CoreDNS ConfigMap and validate that in-addr.arpa and ip6.arpa are listed as wildcards
make sure that in-addr.arpa and ip6.arpa are listed as wildcards next to cluster.local
$ kubectl -n kube-system edit cm coredns

validate this by looking up a pod IP with the host utility from any pod
$ kubectl -n kube-system describe pod coredns-5c98db65d4-7j927 | grep IP
IP:                   10.217.0.247
vagrant@k8s-master01:~$ host 10.217.0.247
Host 247.0.217.10.in-addr.arpa. not found: 3(NXDOMAIN)

restart the pods as well if required and validate that Cilium is managing kube-dns or coredns by running:
$ kubectl -n kube-system get cep

$ kubectl -n kube-system get deployments cilium-operator

the logfile of a pod 
$ kubectl --namespace kube-system logs cilium-l6xnh

Verify that Cilium pods were started on each of your worker nodes
$ kubectl --namespace kube-system get ds cilium
Check the status of the DaemonSet and verify that all desired instances are in “ready” state:
$ kubectl --namespace kube-system get ds
list all cilium pods by matching on the label k8s-app=cilium and also sort the list by the restart count of each pod to easily identify the failing pods:
$ kubectl --namespace kube-system get pods --selector k8s-app=cilium  --sort-by='.status.containerStatuses[0].restartCount'
------------------------------------------------------------------------------------------------

sudo kubeadm init --node-name vgmaster01 --config kubeadm-config.yaml

sudo kubeadm init --apiserver-advertise-address=192.168.10.5

kubeadm init --cri-socket /run/containerd/containerd.sock \
--apiserver-advertise-address="10.217.50.10" \ 
--apiserver-cert-extra-sans="10.217.50.10"  \
--node-name vagrant-k8s-master02 \
--pod-network-cidr=10.217.0.0/16 >> cluster_initialized.txt

sudo kubeadm join 192.168.10.1:6443 --token p72ox8.5khzi65hogql99ol \
--discovery-token-ca-cert-hash sha256:4272ff4ff1bd59c93dfcbd4dbb0780b0cdf838813121940879259d4bcc1906d5 --experimental-control-plane

sudo kubeadm join 192.168.10.1:6443 --token p72ox8.5khzi65hogql99ol \
--discovery-token-ca-cert-hash sha256:4272ff4ff1bd59c93dfcbd4dbb0780b0cdf838813121940879259d4bcc1906d5 \
--experimental-control-plane --v=2
------------------------------------------------------------------------------------------------
#verbose levels
--v=2
--v=3
------------------------------------------------------------------------------------------------
# configuration from the cluster
kubectl -n kube-system get cm kubeadm-config -oyaml
------------------------------------------------------------------------------------------------
# etcd

$ sudo docker run --rm -it --net host -v /etc/kubernetes:/etc/kubernetes k8s.gcr.io/etcd:3.3.10 etcdctl \
 --cert-file /etc/kubernetes/pki/etcd/peer.crt \
 --key-file /etc/kubernetes/pki/etcd/peer.key \
 --ca-file /etc/kubernetes/pki/etcd/ca.crt \
 --endpoints https://192.168.10.2:2379  member list
 2af255134b508f21: name=infra2 peerURLs=https://192.168.10.4:2380 clientURLs=https://192.168.10.4:2379 isLeader=true
 4a451414459653c0: name=infra0 peerURLs=https://192.168.10.2:2380 clientURLs=https://192.168.10.2:2379 isLeader=false
 86ef4da6f07b0d20: name=infra1 peerURLs=https://192.168.10.3:2380 clientURLs=https://192.168.10.3:2379 isLeader=false

$ sudo docker run --rm -it --net host -v /etc/kubernetes:/etc/kubernetes k8s.gcr.io/etcd:3.3.10 etcdctl \
 --cert-file /etc/kubernetes/pki/etcd/peer.crt \
 --key-file /etc/kubernetes/pki/etcd/peer.key \
 --ca-file /etc/kubernetes/pki/etcd/ca.crt \
 --endpoints https://192.168.10.2:2379 --debug cluster-health
 Cluster-Endpoints: https://192.168.10.2:2379
 cURL Command: curl -X GET https://192.168.10.2:2379/v2/members
 member 2af255134b508f21 is healthy: got healthy result from https://192.168.10.4:2379
 member 4a451414459653c0 is healthy: got healthy result from https://192.168.10.2:2379
 member 86ef4da6f07b0d20 is healthy: got healthy result from https://192.168.10.3:2379
 cluster is healthy
 
 $ curl -X GET https://192.168.10.2:2379/v2/members
  curl: (35) gnutls_handshake() failed: Certificate is bad
  
$ sudo curl --cert /etc/kubernetes/pki/etcd/peer.crt --key /etc/kubernetes/pki/etcd/peer.key https://192.168.10.2:2379
  curl: (60) server certificate verification failed. CAfile: /etc/ssl/certs/ca-certificates.crt CRLfile: none
  More details here: http://curl.haxx.se/docs/sslcerts.html  
------------------------------------------------------------------------------------------------
vagrant@remotecontrol01:~$ kubectl delete deployment kubernetes-dashboard --namespace=kube-system
vagrant@remotecontrol01:~$ kubectl get secret,sa,role,rolebinding,services,deployments --namespace=kube-system | grep dashboard

vagrant@remotecontrol01:~$ kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.0-beta1/aio/deploy/recommended.yaml
vagrant@remotecontrol01:~$ kubectl delete -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.0-beta1/aio/deploy/recommended.yaml
------------------------------------------------------------------------------------------------