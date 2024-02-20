# How to install Docker

## Overview

Instructions for installing [Docker](https://www.docker.com/).

For detailed installation, see [Docker docs](https://docs.docker.com/install/).

### Contents

1. [Install](#install)
    1. [CentOS](#centos)
    1. [Ubuntu](#ubuntu)
    1. [macOS](#macos)
    1. [Windows](#windows)
1. [Test](#test)
1. [Troubleshooting](#troubleshooting)
1. [References](#references)

## Install

### CentOS

There are a few methods to install `docker` on Ubuntu.

1. [Default yum install](#centos---default-yum-install)
1. [Docker Community Edition](#centos---docker-community-edition)

#### CentOS - Default yum install

1. Yum install Docker.
   Example:

    ```console
    sudo yum install docker
    ```

1. Start Docker.
   Example:

    ```console
    sudo systemctl start docker
    ```

1. **Optional:** Start Docker on reboot.
   Example:

    ```console
    sudo systemctl enable docker
    ```

#### CentOS - Docker Community Edition

:warning: This may be an out-dated method.

1. Uninstall old docker.
   Example:

    ```console
    sudo yum remove docker docker-common docker-selinux docker-engine
    ```

1. [CentOS](https://docs.docker.com/install/linux/docker-ce/centos/)

    ```console
    sudo yum -y install yum-utils device-mapper-persistent-data lvm2
    sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    sudo yum -y install docker-ce
    ```

1. Start Docker.
   Example:

    ```console
    sudo systemctl start docker
    ```

1. **Optional:** Start Docker on reboot.
   Example:

    ```console
    sudo systemctl enable docker
    ```

1. Fix for unable to prepare context.

    Error seen:

    ```console
    unable to prepare context: unable to 'git clone' to temporary context directory: error initializing submodules: usage: git submodule
    ```

    Fix:

    ```console
    sudo yum install https://centos7.iuscommunity.org/ius-release.rpm
    sudo yum swap git git2u
    ```

### Ubuntu

There a a few methods to install `docker` on Ubuntu.

1. [Default apt install](#ubuntu---default-apt-install)
1. [Docker Community Edition](#ubuntu---docker-community-edition)

#### Ubuntu - Default apt install

1. Apt install Docker.
   Example:

    ```console
    sudo apt install docker.io
    ```

1. Proceed to [Test](#test)

#### Ubuntu - Docker Community Edition

:warning: This may be an out-dated method.

1. [Ubuntu](https://docs.docker.com/install/linux/docker-ce/ubuntu/)

    ```console
    sudo apt-get update

    sudo apt-get install \
        apt-transport-https \
        ca-certificates \
        curl \
        software-properties-common

    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

    sudo add-apt-repository \
       "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
       $(lsb_release -cs) \
       stable"

    sudo apt-get update

    sudo apt-get install docker-ce
    ```

1. Proceed to [Test](#test)

#### Ubuntu - Past edition

1. Past version
   Example:

    ```console
    sudo apt-get update
    sudo apt -y install apt-transport-https ca-certificates curl software-properties-common
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    sudo apt-get update
    sudo apt -y install docker.io
    ```

1. Proceed to [Test](#test)

### macOS

1. [Install Docker Desktop for Mac](https://docs.docker.com/docker-for-mac/install/)
    1. Open Docker.dmg
    1. Drag Docker to Applications

1. Go to "Applications" and double-click on "Docker"
    1. Check the menu bar for the Docker icon

1. Test
    1. Open Terminal

    ```console
    docker --version
    docker-compose --version
    docker-machine --version
    docker run hello-world
    ```

1. Proceed to [Test](#test)

### Windows

1. **Caveat:** Requires Windows Pro.
1. [Install Docker Desktop for Windows](https://docs.docker.com/docker-for-windows/install/)
    1. Run `Docker%20for%20%Windows%20Installer.exe`
1. Proceed to [Test](#test)

## Test

1. Test

    ```console
    sudo docker --version
    sudo docker run hello-world
    ```

## Troubleshooting

## References
