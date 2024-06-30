#!/usr/bin/env bash

_TEMPLATE="nmap -p [v] [k] -oX [k].xml"
_KVSEP=':'

# - - - - - - - - - - - - - - - - - - - - - - -
# example usage:
#
# _TEMPLATE="nmap -p [v] [k] -oX [k].xml"
#
#    targets.txt:
#    127.0.0.1:8080
#    127.0.0.1:9090
#    1.1.1.1:53
#
#~$ bash hashmap.sh targets.txt
#   nmap -p 53 1.1.1.1 -oX 1.1.1.1.xml
#   nmap -p 8080,9090 127.0.0.1 -oX 127.0.0.1.xml
# -------------------------
# ----------- Or ----------
# -------------------------
#~$ cat targets.txt | ./hashmap.sh
#   nmap -p 53 1.1.1.1 -oX 1.1.1.1.xml
#   nmap -p 8080,9090 127.0.0.1 -oX 127.0.0.1.xml
# - - - - - - - - - - - - - - - - - - - - - - - -

[ $# -ge 1 -a -f "$1" ] && cat "$1" | $0 && exit || _IN="-"


declare -A hashmap
while read -r line; do
        _key=$(echo "$line" | awk -F "$_KVSEP" '{print $1}')
        _value=$(echo "$line" | awk -F "$_KVSEP" '{print $2}')
        if [[ ! -v hashmap[$_key] ]]; then
                hashmap[$_key]="$_value";
        else
                _original="${hashmap[$_key]}"
                hashmap[$_key]="$_original,$_value"
        fi
done

# echo -e "\nfound ${#hashmap[@]} unique keys...\n"

for _k in "${!hashmap[@]}"; do
        _v="${hashmap[$_k]}"
        echo "$(echo $_TEMPLATE | sed 's|\[v\]|'$_v'|g' | sed 's|\[k\]|'$_k'|g')"
done
