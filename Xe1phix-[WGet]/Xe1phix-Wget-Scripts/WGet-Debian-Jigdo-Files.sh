#!/bin/sh

## Download all Debian Jigdo files:
wget --show-progress -4 -P ~/Downloads/OS/jigdo/ -nd -r -l 1 -H -D cdimage.debian.org -A jigdo,template https://cdimage.debian.org/debian-cd/current/amd64/jigdo-dvd/
