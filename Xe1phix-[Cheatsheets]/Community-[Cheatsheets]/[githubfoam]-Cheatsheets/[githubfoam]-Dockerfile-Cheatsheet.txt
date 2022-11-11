#=====================================================================
#multi layer dockerfile, use an external image as a “stage”

# syntax=docker/dockerfile:1
FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/alexellis/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go    ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /go/src/github.com/alexellis/href-counter/app ./
CMD ["./app"]  

#=====================================================================
#multi layer dockerfile, use an external image as a “stage”

# syntax=docker/dockerfile:1
FROM alpine:latest AS builder
RUN apk --no-cache add build-base

FROM builder AS build1
COPY source1.cpp source.cpp
RUN g++ -o /binary source.cpp

FROM builder AS build2
COPY source2.cpp source.cpp
RUN g++ -o /binary source.cpp

#=====================================================================
#warning not an error
#debconf: delaying package configuration, since apt-utils is not installed

FROM kalilinux/kali-rolling

#clean start
RUN set -xe && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get update -y && \
    apt-get upgrade -y && \
    apt-get autoremove - && \
    apt-get clean && \    
    apt-get install -y apt-utils && \
    apt-get install -y --no-install-recommends \
    zmap
    
#=====================================================================
#default entrypoint which is /bin/sh -c
#docker run -it centos bash
#entrypoint /bin/sh -c bash
FROM centos:centos7
#=====================================================================
#https://github.com/dockerfile/ubuntu/blob/master/Dockerfile
#default CMD: CMD ["bash"]

docker run -i -t ubuntu
#=====================================================================
#debug docker builds

RUN set -ex && wget -O - https://some.site | wc -l > /number

#If you want the command to fail due to an error at any stage in the pipe, prepend set -o pipefail &&
RUN set -o pipefail && wget -O - https://some.site | wc -l > /number
#=====================================================================
# nmap tooling
# docker build -t alpine/nmap-nse-vuln:latest
# docker run alpine/nmap-nse-vuln:latest nmap -v -A scanme.nmap.org

FROM alpine:latest
RUN set -xe && apk --update add nmap \
                     nmap-scripts 
ENTRYPOINT ["nmap"]
CMD ["-h"]
#=====================================================================
# run bash script within dockerfile
#It's best practice to use COPY instead of ADD when copying from the local file system to the image

RUN mkdir -p /scripts
COPY script.sh /scripts
WORKDIR /scripts
RUN chmod +x script.sh
RUN ./script.sh
#=====================================================================
Always combine RUN apt-get update with apt-get install in the same RUN statement.
RUN apt-get update && apt-get install -y \
    package-bar \
    package-baz \
    package-foo
#=====================================================================    
# Set multiple labels at once, using line-continuation characters to break long lines
LABEL vendor=ACME\ Incorporated \
      com.example.is-beta= \
      com.example.is-production="" \
      com.example.version="0.0.1-beta" \
      com.example.release-date="2015-02-12"
#=====================================================================
The default ENTRYPOINT
/bin/sh -c
#=====================================================================

ENTRYPOINT ["/usr/sbin/init"]
CMD ["systemctl"]

 result:
/usr/sbin/init systemctl

#=====================================================================
Bad: 
RUN apt-get update
RUN apt-get -q -y install lynis

Good:
RUN apt-get update && apt-get -q -y install lynis

RUN apt-get update \
    apt-get -q -y install lsof \
    lynis
# clean up after you are done installing the packages
RUN apt-get update \
    apt-get -q -y install lsof \
    lynis && apt-get clean && rm -rf /var/lib/apt/lists/*  
#=====================================================================

    FROM centos  
    MAINTAINER  @githubfoam   
    #  Set MOFED directory, image and working directory
    ENV MOFED_DIR MLNX_OFED_LINUX-4.2-1.2.0.0-rhel7.4-x86_64
    ENV MOFED_SITE_PLACE MLNX_OFED-4.2-1.2.0.0
    ENV MOFED_IMAGE MLNX_OFED_LINUX-4.2-1.2.0.0-rhel7.4-x86_64.tgz
    WORKDIR /tmp/   
   # Pick up some MOFED dependencies
    RUN yum install -y python-devel pciutils make redhat-rpm-config rpm-build lsof kernel-devel-3.10.0-693.11.1.el7.x86_64 ethtool gcc wget  
   # Download and install Mellanox OFED 4.2-1.2 for Centos 7.4
    RUN wget http://content.mellanox.com/ofed/${MOFED_SITE_PLACE}/${MOFED_IMAGE} && \
            tar -xzvf ${MOFED_IMAGE} && \
            #${MOFED_DIR}/mlnxofedinstall --user-space-only --without-fw-update --all -q && \
            ${MOFED_DIR}/mlnxofedinstall --all --add-kernel-support \
            --kernel3.10.0-693.11.1-generic  --skip-repo -q && \
            cd .. && \
            #rm -rf ${MOFED_DIR} && \
            rm -rf /tmp/${MOFED_DIR} && \
            rm -rf *.tgz
            #rm -rf /tmp/*.tgz
#=====================================================================
    FROM ubuntu:16.04    
    #MAINTAINER @githubfoam #deprecated
    LABEL org.opencontainers.image.authors="githubfoam"
         
    #Set MOFED directory, image and working directory
    ENV MOFED_DIR MLNX_OFED_LINUX-4.2-1.2.0.0-ubuntu16.04-x86_64
    ENV MOFED_SITE_PLACE MLNX_OFED-4.2-1.2.0.0
    ENV MOFED_IMAGE MLNX_OFED_LINUX-4.2-1.2.0.0-ubuntu16.04-x86_64.tgz
    WORKDIR /tmp/    
    # Pick up some MOFED dependencies
    RUN apt-get update && apt-get install -y --no-install-recommends \
            wget \
            net-tools \
            ethtool \
            perl \
            lsb-release \
            iproute2 \
            pciutils \
            libnl-route-3-200 \
            kmod \
            libnuma1 \
            lsof \
            linux-headers-4.4.0-92-generic \
            python-libxml2 && \
            rm -rf /var/lib/apt/lists/*
    # Download and install Mellanox OFED 4.2.1.2 for Ubuntu 16.04
    RUN wget http://content.mellanox.com/ofed/${MOFED_SITE_PLACE}/${MOFED_IMAGE} && \
            tar -xzvf ${MOFED_IMAGE} && \
            ${MOFED_DIR}/mlnxofedinstall --user-space-only --without-fw-update --all -q && \
            cd .. && \
            rm -rf ${MOFED_DIR} && \
            rm -rf *.tgz
#=====================================================================
FROM centos
ADD centos-7-docker.tar.xz /

LABEL name="CentOS Official Docker Image" \
    vendor="CentOS" \
    license="GPLv2" \
    build-date="20170911"

CMD ["/bin/bash"]

FROM centos:7
MAINTAINER The CentOS Project <cloud-ops@centos.org>
LABEL Vendor="CentOS" \
      License=GPLv2 \
      Version=2.4.6-40


RUN yum -y --setopt=tsflags=nodocs update && \
    yum -y --setopt=tsflags=nodocs install httpd && \
    yum clean all

EXPOSE 80

# Simple startup script to avoid some issues observed with container restart
ADD run-httpd.sh /run-httpd.sh
RUN chmod -v +x /run-httpd.sh

CMD ["/run-httpd.sh"]
#=====================================================================
FROM debian:jessie-slim
LABEL version="1.0"
LABEL description="First image with Dockerfile."


RUN apt-get update && \
  apt-get install -y airmon-ng && \
  rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["airmon-ng"]
CMD ["--help"]
#=====================================================================
# extra metadata
LABEL version="1.0"
LABEL description="First airmon-ng image with Dockerfile."

# set the base image
FROM debian

# update sources list
RUN apt-get clean

# add scripts to the container
ADD .bashrc /root/.bashrc
ADD .profile /root/.profile

# add the application to the container
ADD app /app

# locales to UTF-8
# RUN locale-gen C.UTF-8 && /usr/sbin/update-locale LANG=C.UTF-8
# ENV LC_ALL C.UTF-8

# app environment
# ENV PYTHONIOENCODING UTF-8
# ENV PYTHONPATH /app/
#=====================================================================
#heredoc - multi lines 

RUN sh -c "$(/bin/echo -e "cat > /entrypoint.sh <<EOF\
\n#!/bin/bash\
\necho 3\
\necho 2\
\necho 1\
\necho run\
\nEOF\n")"

RUN printf '#!/bin/bash\necho 3\necho 2\necho 1\necho run' > /entrypoint.sh

RUN echo -e " #!/bin/bash\n\
echo 3\n\
echo 2\n\
echo 1\n\
echo run" > /entrypoint.sh

#printf
RUN printf '#!/bin/bash\n\
echo hello world from line 1\n\
echo hello world from line 2'\
>> /tmp/hello

#echo
RUN echo -e '#!/bin/bash\n\
echo hello world from line 1\n\
echo hello world from line 2'\
>> /tmp/hello

bash -c "$(/bin/echo -e "cat > /etc/my.config <<EOM\
\n########################################################\
\n# The file\
\n########################################################\
\na = b\
\nEOM\n")

RUN echo 'All of your\n\
multiline that you ever wanted\n\
into a dockerfile\n'\
>> /etc/example.conf

#=====================================================================
#heredoc - multi lines 

FROM photon:1.0

ARG BASEURL="https://vmware.bintray.com/powershell"

RUN echo $'[powershell]\n\
name=VMware Photon Linux 1.0(x86_64)\n\
baseurl='$BASEURL$'\n\
gpgcheck=0\n\
enabled=1\n\
skip_if_unavailable=True\n '\
>> /etc/yum.repos.d/powershell.repo

CMD ["/bin/bash"]
#=====================================================================
# DOCKERFILE WINDOWS
#=====================================================================
RUN Invoke-WebRequest ('http://de.apachehaus.com/downloads/httpd-{0}-o111l-x64-vc15.zip' -f $env:APACHE_VERSION) -OutFile 'apache.zip' -UseBasicParsing ; \
    Expand-Archive apache.zip -DestinationPath C:\ ; \
    Remove-Item -Path apache.zip
#=====================================================================
#run powershell script dockerfile
FROM mcr.microsoft.com/windows/servercore:20H2 AS PS
SHELL ["powershell"]
RUN Write-Host "Hello from docker! Today is $(Get-Date)"

SHELL ["cmd", "/S", "/C"]    
RUN powershell -noexit "& ""C:\Chocolatey\lib\chocolatey.0.10.8\tools\chocolateyInstall.ps1"""

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
WORKDIR C:\
RUN .\install_pfx.ps1

FROM microsoft/windowsservercore
ADD hello.ps1 .
ADD world.ps1 .
CMD powershell .\hello.ps1 ; .\world.ps1
#=====================================================================
#Docker Image Size

Use a Smaller Image Base (Alpine),Alpine is only 5 MB.
Use a .dockerignore File,initiated with docker run.
Utilize the Multi-Stage Builds,
Avoid Adding Unnecessary Layers

Each RUN instruction in a Dockerfile adds a new layer,
file manipulation inside a single RUN command,combine different commands into one instruction using the && option
one instruction using the && option.

#clean up apt cache with && rm -rf /var/lib/apt/lists/* to save up some more space
RUN apt-get update && apt-get install -y\
         [package-one] \
         [package-two] 
   && rm -rf /var/lib/apt/lists/*   

clean up the rpm cache and add the dnf clean all option
RUN dnf -y update && dnf clean all
RUN yum -y update && yum clean all

# to not cache the index locally
RUN apk add --no-cache

#download only the main dependencies, add the --no-install-recommends 
RUN apt-get install --no-install-recommends wget
#=====================================================================

