

----
Share via #!/usr/bin/env bash

# Author: m8r0wn
# Description: Uses the Linux net commands to lookup a user in Active Directory
# This is the Linux equivalent of: net user [Username] /domain
# Usage: ./aduser_lookup.sh [username] [password] [DC-Server] [Lookup-User]

if [ ! $1 ];
then
	printf "[-] Usage: $0 Username Password DC_Server username_to_lookup\n"
	exit 0
fi

#Get info about single user in AD
printf "\nAD User Lookup:\n"
printf '%s\n' '-----------------------'
printf "user edit fullname '$4'"| net rpc shell -U "$1"%"$2" -S $3|tail -n +2
printf "user edit homedir '$4'" | net rpc shell -U "$1"%"$2" -S $3|tail -n +2
printf "user edit homedrive '$4'" | net rpc shell -U "$1"%"$2" -S $3|tail -n +2
printf "user edit logonscript '$4'" | net rpc shell -U "$1"%"$2" -S $3|tail -n +2
printf "user edit profilepath '$4'" | net rpc shell -U "$1"%"$2" -S $3|tail -n +2
printf "user edit description '$4'" | net rpc shell -U "$1"%"$2" -S $3|tail -n +2
printf "user edit disabled '$4'" | net rpc shell -U "$1"%"$2" -S $3|tail -n +2

output="$(printf "user edit autolock '$4'" | net rpc shell -U "$1"%"$2" -S $3|tail -n +2)"
printf "${output} (Currently locked out)\n"

#find users with password not set to change or no expiration
output="$(printf "user edit pwnotreq '$4'" | net rpc shell -U "$1"%"$2" -S $3|tail -n +2)"
printf "${output} (Password not required)\n"

output="$(printf "user edit pwnoexp '$4'" | net rpc shell  -U "$1"%"$2" -S $3|tail -n +2)"
printf "${output} (Password never expire?)\n"

printf "\nGroup Memberships:\n"
printf '%s\n' '-----------------------'
printf "user info '$4'" | net rpc shell -U "$1"%"$2" -S $3|tail -n +2
printf "\n"