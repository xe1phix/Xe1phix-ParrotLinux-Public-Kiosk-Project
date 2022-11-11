openshift-all-in-one 

#web
https://10.2.2.2:8443/console/
admin/admin

#CLI
oc login https://10.2.2.2:8443
admin/admin

#create an application using a remote Git repository
oc new-app https://github.com/<your_user>/<your_git_repo>

#start new project
oc new-project innovation-2016
oc new-project beegfs-lab1

#deploy new docker image on this project
oc new-app gitlab/gitlab-ce
oc new-app redcoolbeans/beegfs-storage

#using project "dockertry" on server "https://10.2.2.2:8443"
oc new-project dockertry
#add applications to this project with the 'new-app' command
oc new-app centos/ruby-22-centos7~https://github.com/openshift/ruby-ex.git


oc status
oc version
systemctl status openshift -l
oc get templates -n openshift

#S2I openshift example
docker search wildfly-100-centos7
oc new-app openshift/wildfly-100-centos7~https://github.com/fmarchioni/mastertheboss   --context-dir=openshift-demo --name=demo-wildfly
oc logs -f bc/demo-wildfly
oc status

docker search suricata
oc new-app dtagdevsec/suricata
oc new-app mpepping/cyberchef

#check that the Image streams
oc get is
oc get svc
oc expose svc demo-wildfly
oc expose service nodejs-basic
oc get routes
oc get services

#test app
curl http://nodejs-basic-myproject.192.168.1.66.xip.io


sudo gunzip Downloads/occli/openshift-origin-client-tools-v1.1.1-e1d9873-linux-64bit.tar.gz
sudo tar -xf openshift-origin-client-tools-v1.1.1-e1d9873-linux-64bit.tar 
mkdir occli
export PATH=$PATH:~/cli/
export PATH=$PATH:~/home/bart/Downloads/occli/openshift-origin-client-tools-v1.1.1-e1d9873-linux-64bit/
echo $PATH


