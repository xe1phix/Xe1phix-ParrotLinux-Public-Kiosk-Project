# Docker
## Install Docker on Debian
```
sudo apt-get update && sudo apt-get upgrade
sudo apt-get install apt-transport-https ca-certificates curl gnupg2 software-properties-common
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable"
sudo apt-get update && sudo apt-get install docker-ce docker-compose
sudo usermod -aG docker <user>
```

## Container constantly crashing on Debian Buster
If containers constantly crash (with error 139) and you see the following errors in system logs:
```
kernel: [  281.151742] docker-entrypoi[5982] vsyscall attempted with vsyscall=none ip:ffffffffff600400 cs:33 sp:7ffee8a01378 ax:ffffffffff600400 si:7ffee8a02e51 di:0
kernel: [  281.151744] docker-entrypoi[5982]: segfault at ffffffffff600400 ip ffffffffff600400 sp 00007ffee8a01378 error 15
```

You need to use the "vsyscall=emulate" kernel parameter. Edit /etc/default/grub as such:
```
GRUB_CMDLINE_LINUX_DEFAULT="quiet vsyscall=emulate"
```

Then do:
```
sudo update-grub
sudo reboot
```

## Cleanup docker resources
```
sudo docker system prune --volumes 
```

This will remove:
- all stopped containers
- all networks not used by at least one container
- all volumes not used by at least one container
- all dangling images
- all build cache

## Various commands
```
docker run debian echo "Hello World"
docker run -i -t debian /bin/bash

docker run -h CONTAINER -i -t debian /bin/bash

docker ps
docker ps -a # includes stopped containers

docker inspect laughing_ardinghelli
docker diff laughing_ardinghelli

docker run -it --name cowsay --hostname cowsay debian bash
container$ apt-get update
container$ apt-get install -y cowsay fortune
container$ /usr/games/fortune | /usr/games/cowsay
docker commit cowsay test/cowsayimage

docker images -a # show all docker images

docker build -t test/cowsay-dockerfile . # build image from Dockerfile

docker run --name myredis -d redis # run container in the background

docker run -v /path/on/host:/path/on/container:ro my/image # mount volume read-only

docker run --rm ... # automatically remove the container when it exists

docker run -u 1000 --volume $SSH_AUTH_SOCK:/ssh-agent --env SSH_AUTH_SOCK=/ssh-agent test/debian-with-user ssh-add -l

docker run --volume $SSH_AUTH_SOCK:/ssh-agent --env SSH_AUTH_SOCK=/ssh-agent test/debian-with-user ssh-add -l

docker build -t test/ansibler .
docker run -it -v ~/.ssh/:/home/ansibler/.ssh/:ro -v $SSH_AUTH_SOCK:/ssh-agent test/ansibler

# Copy file from container to host
docker cp <containerId>:/file/path/within/container /host/path/target

# Get private IP of container from host
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' container_name_or_id
```

## Stub dockerfile for a Ansible container
```
FROM debian:stretch

RUN apt-get update && apt-get install -y \
    ansible \
    git \
    openssh-client; \
    groupadd -g 1000 ansibler && useradd -g ansibler -m -u 1000 ansibler; \
    mkdir /home/ansibler/.ssh/ && chown ansibler:ansibler /home/ansibler/.ssh && chmod 0700 /home/ansibler/.ssh

ENV SSH_AUTH_SOCK=/ssh-agent
USER ansibler
WORKDIR /home/ansibler

ENTRYPOINT ["/bin/bash"]
```
