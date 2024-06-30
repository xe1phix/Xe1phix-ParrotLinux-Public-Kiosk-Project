#!/bin/bash
#
# GnuTLS CA Script
# 
# Author: sskaje
#
# This content is released under the MIT License (MIT)
#
# Copyright (c) 2015 sskaje
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# Path to CA root
CAROOT=~/Documents/CA
CERTTOOL=/opt/gnutls/bin/certtool

function usage()
{
    cat <<USAGE

GnuTLS CA Script
Author: sskaje http://sskaje.me/
Usage:
    /path/to/ca.sh 
        genca   NAME            generate self signed 
        genkey  NAME [KEYBITS]  generate private key, NAME-key.pem, default KEYBITS=2048
        genreq  NAME            generate certification request, NAME.tmpl required, NAME-cert.csr
        signreq NAME CA_NAME    create certificate from NAME-cert.csr, NAME-cert.pem
        to_p12  NAME [CA_NAME]  export to pkcs#12 NAME.p12, ca cert included if CA_NAME is valid
        p7sign  NAME CA_NAME    sign NAME to NAME.signed, gnutls 3.4.x+ required
        gencrl  NAME CA_NAME    create CRL, NAME-crl.pem

USAGE

    exit
}

if [ $# -lt 2 ]; then
    echo "Missing name"
    usage

    exit
fi

if [ -z $CERTTOOL ]; then
    CERTTOOL=`which gnutls-certtool`
fi
if [ -z $CERTTOOL ]; then
    CERTTOOL=certtool
fi

CAPATH=
CACERT=
CAKEY=
KEYBITS=2048

function require_template()
{
    if [ ! -f $1.tmpl ]; then
        echo "$1.tmpl not found"
        exit
    fi
}

function to_upper()
{
    echo $1 | tr '[a-z]' '[A-Z]'
}

function to_lower()
{
    echo $1 | tr '[A-Z]' '[a-z]'
}

function capath()
{
    local UPPERNAME=$(to_upper $1)
    local LOWERNAME=$(to_lower $1)
    CAPATH="$CAROOT/${UPPERNAME} CA/${LOWERNAME}_ca"
}

function cakey()
{
    capath $1
    CAKEY="${CAPATH}.key"

    if [ ! -f "${CAKEY}" ]; then
        echo "${CAKEY}" not found
        exit
    fi
}

function cacert()
{
    capath $1
    CACERT="${CAPATH}.pem"

    if [ ! -f "${CACERT}" ]; then
        echo $CACERT not found
        exit
    fi
}

function ca_load()
{
    cacert $1
    cakey  $1
}

function genca()
{
    if [ ! -f $1-key.pem ]; then
        echo "Run \`ca.sh genkey $1\` first"
        exit
    fi
    echo $CERTTOOL --generate-self-signed --load-privkey $1-key.pem --template $1.tmpl --outfile $1-cert.pem
    $CERTTOOL --generate-self-signed --load-privkey $1-key.pem --template $1.tmpl --outfile $1-cert.pem
}

function genkey()
{
    if [ $# -gt 1 ]; then
        if [ $2 -ge 1024 ]; then
            KEYBITS=$2
        fi
    fi

    echo $CERTTOOL --generate-privkey --outfile $1-key.pem 
    $CERTTOOL --generate-privkey --bits $KEYBITS --outfile $1-key.pem 
}

function genreq()
{
    require_template $1
    echo $CERTTOOL --generate-request --load-privkey $1-key.pem --template $1.tmpl --outfile $1-cert.csr
    $CERTTOOL --generate-request --load-privkey $1-key.pem --template $1.tmpl --outfile $1-cert.csr
}

function signreq()
{
    require_template $1
    ca_load $2
    echo $CERTTOOL --generate-certificate --load-request $1-cert.csr --load-ca-certificate "'${CACERT}'" --load-ca-privkey "'${CAKEY}'" --template $1.tmpl --outfile $1-cert.pem
    $CERTTOOL --generate-certificate --load-request $1-cert.csr --load-ca-certificate "${CACERT}" --load-ca-privkey "${CAKEY}" --template $1.tmpl --outfile $1-cert.pem
}

function to_p12()
{
    if [ $2 != "" ];
    then 
        ca_load $2

        echo $CERTTOOL --load-ca-certificate "'${CACERT}'" --load-certificate $1-cert.pem --load-privkey $1-key.pem --to-p12 --p12-name="$1" --outder --outfile $1.p12
        $CERTTOOL --load-ca-certificate "${CACERT}" --load-certificate $1-cert.pem --load-privkey $1-key.pem --to-p12 --p12-name="$1" --outder --outfile $1.p12
    else
        echo $CERTTOOL --load-certificate $1-cert.pem --load-privkey $1-key.pem --to-p12 --p12-name="$1" --outder --outfile $1.p12
        $CERTTOOL --load-certificate $1-cert.pem --load-privkey $1-key.pem --to-p12 --p12-name="$1" --outder --outfile $1.p12
    fi
}

function p7sign()
{
    ca_load $2
    echo $CERTTOOL --p7-sign --p7-include-cert --load-privkey "'${CAKEY}'" --load-certificate "'${CACERT}'" --infile $1 --outder --outfile $1.signed
    $CERTTOOL --p7-sign --p7-include-cert --load-privkey "${CAKEY}" --load-certificate "${CACERT}" --infile $1 --outder --outfile $1.signed
}

function gencrl()
{
    ca_load $2
    echo $CERTTOOL --generate-crl --load-ca-privkey "'${CAKEY}'"  --load-ca-certificate "'${CACERT}'" --template $1.tmpl --outfile $1-crl.pem
    $CERTTOOL --generate-crl --load-ca-privkey "${CAKEY}"  --load-ca-certificate "${CACERT}" --template $1.tmpl --outfile $1-crl.pem
}

case $1 in 
    genca) 
        genca $2
        ;;

    genkey)
        genkey $2 $3
        ;;

    genreq)
        genreq $2
        ;;

    signreq)
        signreq $2 $3
        ;;

    sign)
        signreq $2 $3
        ;;

    to_p12)
        to_p12 $2 $3
        ;;

    p7sign)
        p7sign $2 $3
        ;;

    gencrl)
        gencrl $2 $3
        ;;

    *)
        usage
        ;;
esac

# EOF
