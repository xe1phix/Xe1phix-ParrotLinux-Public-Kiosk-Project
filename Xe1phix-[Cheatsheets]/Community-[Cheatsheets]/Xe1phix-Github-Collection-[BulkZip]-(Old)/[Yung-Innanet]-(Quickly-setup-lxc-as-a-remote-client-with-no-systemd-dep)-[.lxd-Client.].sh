#!/usr/bin/env bash
_port=${LXD_PORT:-"8443"}
_fqdn=${LXD_FQDN:-"ebaumsworld.com"}
set -e
function req {
	go version || return 1
	git version || return 1
	ssh -V || return 1
}
req || exit 1
export CGO_ENABLED=0
if [ "$_fqdn" == "ebaumsworld.com" ]; then
	echo "enter fqdn for lxd endpoint for which you have permissions:"
	read -r _fqdn
fi
exec 3<>"/dev/tcp/$_fqdn/$_port" || ssh "$_fqdn" "lxc config set core.https_address '[::]:8443'" || exit 1
# warm user account to assert that we have a certificate associated with the user in the case that it's new
ssh $_fqdn "lxc list" > /dev/null
token="$(ssh "$_fqdn" 'lxc config trust add --name $(whoami)' | grep -v token)" || exit 1
git clone https://github.com/lxc/lxd || cd lxd || exit 1
cd lxd/lxc || exit 1
go build -v ./ || exit 1
mv lxc ~/.local/bin/ || exit 1
# following optional if you already have this in your path
echo 'export PATH=$HOME/.local/bin:$PATH' >>~/.bashrc
source ~/.bashrc
# but you need these \/
lxc remote add "$_fqdn" "$token"
lxc remote set-default "$_fqdn"
lxc list
