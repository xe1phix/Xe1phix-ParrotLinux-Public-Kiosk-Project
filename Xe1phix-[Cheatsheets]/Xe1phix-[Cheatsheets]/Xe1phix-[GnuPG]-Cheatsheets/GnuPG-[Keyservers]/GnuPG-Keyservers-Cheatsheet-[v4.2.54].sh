#!/bin/sh
gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x
gpg --keyserver hkp://jirk5u4osbsr34t5.onion --recv-keys 0x
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x
gpg --keyserver subkeys.pgp.net --recv-keys 0x
gpg --keyserver keys.gnupg.net --recv-keys 0x
gpg --keyserver keys.riseup.net --recv-keys 0x
gpg --keyserver ldap://keyserver.pgp.com --recv-keys 0x
gpg --keyserver keys.inscrutable.i2p --recv-keys 0x
gpg --keyserver pgpkeys.mit.edu --recv-keys 0x
gpg --keyserver keyserver.ubuntu.com --recv-keys 0x
gpg --keyserver keyserver.opensuse.org --recv-keys 0x
gpg --keyserver keys.fedoraproject.org --recv-keys 0x
gpg --keyserver keys.i2p-projekt.de --recv-keys 0x
