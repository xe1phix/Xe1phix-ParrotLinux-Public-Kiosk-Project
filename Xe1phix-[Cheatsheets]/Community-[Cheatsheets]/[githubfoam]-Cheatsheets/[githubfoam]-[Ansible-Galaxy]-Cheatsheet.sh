============================================================================
$ ansible-galaxy --version
ansible-galaxy 2.4.2.0
============================================================================
ansible-galaxy install --roles-path . -r requirements.yml
ansible-galaxy --offline init role_name
============================================================================
ansible-galaxy install -r requirements.yml
ansible-playbook playbook.yml -i inventory 
============================================================================
ANSIBLE_ROLES_PATH -> The default path is /etc/ansible/roles
ANSIBLE_ROLES_PATH -> Ansible Galaxy saves every role you install and look when resolving the imports from your playbook
============================================================================
ansible-galaxy init role_name -> Initialize the base structure of a new role
ansible-galaxy search *jenkins* -> List of roles filtered
ansible-galaxy install geerlingguy.jenkins -> Download roles from the Galaxy website
============================================================================
Find ansible role's id in ansible-galaxy -> ansible-galaxy info YourUser.RoleName | grep -E 'id: [0-9]' | awk {'print $2'}
View all ansible role details -> ansible-galaxy info YourUser.RoleName
============================================================================
 cat requirements.yml
 - src: zaiste.essentials
- src: zaiste.nginx
- src: williamyeh.oracle-java
- src: zaiste.security

 cat requirements.yml
# from galaxy
- src: userone.roleone
- src: usertwo.roleone
- src: usertwo.roletwo

# Save and install
ansible-galaxy install -r requirements.yml

cat > requirements.yml << EOF
- name: ansible-consul
  src: https://github.com/jamescarr/ansible-consul.git
EOF

# install a role directly from Github
- name: essentials
  src: https://github.com/zaiste/ansible-essentials
# install a role directly from Github using a specific branch
- name: essentials
  src: https://github.com/zaiste/ansible-essentials
  version: origin/master
 # install a role directly from Github using a specific tag
 - name: essentials
  src: https://github.com/zaiste/ansible-essentials
  version: 0.0.3
 # install a role directly from Github using a specific commit SHA1
 - name: essentials
  src: https://github.com/zaiste/ansible-essentials
  version: <sha1>
 # From a webserver
 # where the role is packaged in a tar.gz
- src: https://webserver.example.com/files/master.tar.gz
name: http-role
 ============================================================================
 # Install Ansible
 pip install ansible
 # install Ansible (preferably) in a dedicated python virtualenv using the
 # pip python package manager
 pip install virtualenv
 virtualenv myproject
 ". myproject/bin/activate"
 (myproject) pip install Ansible==2.1.4.0
  ============================================================================
 ansible
ansible-console
ansible-container
ansible-doc
ansible-galaxy
ansible-lint
ansible-playbook
ansible-pull
ansible-vault
============================================================================
# Ansible galaxy, github and Travis
cat .travis.yml

language: python
python: "2.7"
addons:
apt:
packages:
- python-pip
install:
- pip install ansible
script:
- ansible-playbook tests/test.yml -i tests/inventory \
--syntax-check
notifications:
webhooks: https://galaxy.ansible.com/api/v1/notifications/
============================================================================
# role template dir
.gitlab-ci.yml
README.md
ansible.cfg
defaults/main.yml
files/
install_roles.yml
handlers/main.yml
meta/main.yml
templates/
test.yml
production.yml
requirements.txt
vars/main.yml
============================================================================
CI tests in Docker containers.CI file
test:
image: python:2.7
script:
- apt-get update -y && \
apt-get install -y python python-dev python-pip
- pip install -r requirements.txt
- echo localhost > inventory
- ansible-playbook -i inventory \
test.yml --connection=local
============================================================================
# Ansible-galaxy template
ansible-galaxy init --role-skeleton=/path/to/skeleton role_nam

OR
cat ansible.cfg
[galaxy]
role_skeleton = /path/to/skeleton
role_skeleton_ignore = ^.git$,^.*/.git_keep$
============================================================================
# Create a git project where you put the role template and run git clone instead of
# ansible-galaxy init
============================================================================
vars:
  key_file: /etc/nginx/ssl/nginx.key
  cert_file: /etc/nginx/ssl/nginx.crt
  conf_file: /etc/nginx/sites-available/default
  server_name: localhost
  
vars_files:
 - nginx.yml
 
 nginx.yml
 key_file: /etc/nginx/ssl/nginx.key
cert_file: /etc/nginx/ssl/nginx.crt
conf_file: /etc/nginx/sites-available/default
server_name: localhost
 

============================================================================
- name: show return value of command module
  hosts: server1
  tasks:
    - name: capture output of id command
      command: id -un
      register: login
    - debug: var=login
============================================================================
- name: capture output of id command
  command: id -un
  register: login
- debug: msg="Logged in as user {{ login.stdout }}"
============================================================================
- name: print out operating system
  hosts: all
  gather_facts: True
  tasks:
  - debug: var=ansible_distribution
============================================================================
- name: print ansible_local
  debug: var=ansible_local
- name: print book title
  debug: msg="The title of the book is {{ ansible_local.example.book.title }}"
  
  https://www.oreilly.com/library/view/ansible-up-and/9781491915318/ch04.html
============================================================================
# run ansible role locally

ansible-galaxy install -r requirements.yml
sudo ansible-playbook apache_playbook.yml

$ cat requirements.yml
- src: githubfoam.apache
$ cat apache_playbook.yml
---
- hosts: localhost
  roles:
  - githubfoam.apache
============================================================================