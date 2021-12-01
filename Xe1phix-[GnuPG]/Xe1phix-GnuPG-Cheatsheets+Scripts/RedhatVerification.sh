#!/bin/sh
######
## RedhatVerification.sh
######


# The two fingerprints below are retrieved from https://access.redhat.com/security/team/key
REDHAT_RELEASE_2_FINGERPRINT="567E 347A D004 4ADE 55BA 8A5F 199E 2F91 FD43 1D51"
REDHAT_AUXILIARY_FINGERPRINT="43A6 E49C 4A38 F4BE 9ABF 2A53 4568 9C88 2FA6 58E0"

# Location of the key we would like to import (once it's integrity verified)
REDHAT_RELEASE_KEY="/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
