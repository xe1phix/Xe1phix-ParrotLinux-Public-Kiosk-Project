#!/usr/bin/env bash

# This script scans the kubernetes resources for images with specified vulneratibilities. Modified from: https://medium.com/linkbynet/cve-2021-44228-finding-log4j-vulnerable-k8s-pods-with-bash-trivy-caa10905744d.
# Requirements:
# - kubectl
# - trivy
# - trivy k8s plugin: https://github.com/aquasecurity/trivy-plugin-kubectl

RED='\033[0;31m'
NC='\033[0m'

OLDIFS="$IFS"
IFS=$'\n'
VULN=$1

# $1 arg is the CVE number to check
if [ -z $1 ]; then
  echo -e "usage: $0 CVE-NUMBER (i.e: './k8s_vuln.sh CVE-2021-44228')"
  exit
fi

# Check command existence before using it
if ! command -v trivy &> /dev/null; then
  echo "trivy not found, please install it and the the k8s plugin: https://github.com/aquasecurity/trivy-plugin-kubectl"
  exit
fi
if ! command -v kubectl &> /dev/null; then
  echo "kubectl not found, please install it"
  exit
fi

# CVE-2021-44228
echo "Scanning $1..."

scan_resource()
{
    RESOURCE_TYPE=$1
    NAMESPACE=$2
    VULNERABILITY=$3
    echo "  scanning ${RESOURCE_TYPE}"
    resources=`kubectl get ${RESOURCE_TYPE} -n ${NAMESPACE} | awk '(NR>1)'| awk '{ print $1 }'`
    for resource in ${resources}; do
        echo "    scanning ${RESOURCE_TYPE} ${resource}"
        result=`trivy kubectl ${RESOURCE_TYPE} ${resource} -n ${NAMESPACE} -- --severity CRITICAL`
        if echo ${result} | grep -q "$VULNERABILITY" ; then
        echo -e "    ${RED}${RESOURCE_TYPE} ${resource} is vulnerable, please patch!${NC}"
        fi
    done
}

namespaces=`kubectl get ns | cut -d' ' -f 1 | tail -n+2`
for ns in ${namespaces}; do
  echo "- scanning in namespace ${ns}"
  scan_resource deployment ${ns} $1
  scan_resource daemonset ${ns} $1
  scan_resource statefulset ${ns} $1
  scan_resource job ${ns} $1
  scan_resource cronjob ${ns} $1
done