#!/bin/sh

scriptname=`basename $0`
if [ -z $1 ]; then
    echo "Generate OATH TOTP Password"
    echo ""
    echo "Usage:"
    echo "   $scriptname google"
    echo ""
    echo "Configuration: $HOME/.otpkeys"
    echo "Format: name:key"
    echo 
    echo "Preferably encrypt with gpg --armor to create .opkeys.asc"
    echo "and then delete .optkeys"
    echo ""
    echo "Optionally set OTPKEYS_PATH environment variable to GPG"
    echo "with path to GPG encrypted name:key file."
    exit
fi

if [ -z "$(which oathtool)" ]; then
    echo "othtool not found in \$PATH"
    echo "try:"
    echo "MacPorts: port install oath-toolkit"
    echo "Debian:   apt-get install oathtool"
    echo "Red Hat:  yum install oathtool"
    exit
fi

if [ -z "$OTPKEYS_PATH" ]; then
    if [ -f "$HOME/.otpkeys.asc" ]; then
        otpkeys_path="$HOME/.otpkeys.asc"
    else
        otpkeys_path="$HOME/.otpkeys"
    fi
else
    otpkeys_path=$OTPKEYS_PATH
fi

if [ -z "$otpkeys_path" ]; then
    >&2 echo "You need to create $otpkeys_path"
    exit 1
fi

if [ "$otpkeys_path" = "$HOME/.otpkeys" ]; then 
    red='\033[0;31m'
    NC='\033[0m' # No Color
    
    >&2 echo "${red}WARNING: unencrypted ~/.otpkeys"
    >&2 echo "do: gpg --encrypt --recipient your-email --armor ~/.otpkeys"
    >&2 echo "and then delete ~/.otpkeys"
    >&2 echo "${NC}"
    otpkey=`grep ^$1 "$otpkeys_path" | cut -d":" -f 2 | sed "s/ //g"`
else 
    otpkey=`gpg --batch --decrypt "$otpkeys_path" 2> /dev/null | grep "^$1:" | cut -d":" -f 2 | sed "s/ //g"`
fi

if [ -z "$otpkey" ]
then
    echo "$scriptname: TOTP key name not found"
    exit
fi
oathtool --totp -b "$otpkey"

