#! /bin/bash
set -e

if ! [ -d kernel -a -d Documentation ]
then
    echo >&2 "Not in kernel top level directory. Exiting"
    exit 1
fi
TOPPATCHDIR=/usr/src/kernel-patches
ARCHITECTURE=`dpkg --print-architecture`
DECOMPRESSOR="zcat -f"
PATCH_OPTIONS="--ignore-whitespace --silent"
# This is informational only, used by lskpatches
DHPKPATCHES_VERSION=0.99.36+nmu1

DEPENDS=("" "")

KVERSIONS=(3.2.21 2.6.32)
PATCHFILES=("/usr/src/kernel-patches/diffs/grsecurity2/grsecurity-2.9.1-3.2.21-201206221855.patch.gz" "/usr/src/kernel-patches/diffs/grsecurity2/grsecurity-2.9.1-2.6.32.59-201206221854.patch.gz")
DEBPATCHFILES=("" "")
STRIPLEVELS=(1 1)

[ -f debian/APPLIED_${ARCHITECTURE}_grsecurity2 -o \
  -f debian/APPLIED_all_grsecurity2 ] && exit 0
VERSION=$(grep ^VERSION Makefile 2>/dev/null | \
        sed -e 's/[^0-9]*\([0-9]*\)/\1/')
PATCHLEVEL=$( grep ^PATCHLEVEL Makefile 2>/dev/null | \
        sed -e 's/[^0-9]*\([0-9]*\)/\1/')
SUBLEVEL=$(grep ^SUBLEVEL Makefile 2>/dev/null | \
        sed -e 's/[^0-9]*\([0-9]*\)/\1/')
EXTRAVERSION=$(grep ^EXTRAVERSION Makefile | head -1 2>/dev/null | \
        sed -e 's/EXTRAVERSION =[       ]*\([^  ]*\)$/\1/')
KERNELBRANCHLET=${VERSION}.${PATCHLEVEL}.${SUBLEVEL}
KERNELRELEASE=${KERNELBRANCHLET}${EXTRAVERSION}
IDX=

declare -i i=${#PATCHFILES[*]}-1
while [ $i -ge 0 ]
do
    v=${KVERSIONS[$i]}
    if [ -n "$KPATCH_grsecurity2" -a "$v" = "$KPATCH_grsecurity2" \
         -o "$v" = "$KERNELRELEASE" \
         -o "$v" = "$KERNELBRANCHLET" \
         -o "$v" = all ]
    then
        IDX=$i
    fi
    i=i-1
done

if [ -n "$KPATCH_grsecurity2" -a ${KVERSIONS[$IDX]} != "$KPATCH_grsecurity2" ]
then
    echo >&2 "Requested kernel version \`$KPATCH_grsecurity2' not found for patch grsecurity2"
    exit 1
elif [ -z "$IDX" ]
then
    echo >&2 "No \"Greater Security for Linux 2.6 and 3.x\" patch found for kernel version $KERNELRELEASE"
    exit 1
fi
KVERSION=${KVERSIONS[$IDX]}
STRIPLEVEL=${STRIPLEVELS[$IDX]}

if [ "${DEBPATCHFILES[$IDX]}" != '' -a \
    \( -r version.Debian -o -r README.Debian \) ]
then
    PATCHFILE=${DEBPATCHFILES[$IDX]}
else
    PATCHFILE=${PATCHFILES[$IDX]}
fi

echo >&2 "START applying grsecurity2 patch (Greater Security for Linux 2.6 and 3.x)"

NEEDED_DEPS=
for dep in ${DEPENDS[$IDX]}
do
    if [ -x ${TOPPATCHDIR}/${ARCHITECTURE}/${KERNELBRANCHLET}/apply/$dep ]
    then
        NEEDED_DEPS="${ARCHITECTURE}/${KERNELBRANCHLET}/apply/$dep $NEEDED_DEPS"
    elif [ -x ${TOPPATCHDIR}/all/${KERNELBRANCHLET}/apply/$dep ]
    then
        NEEDED_DEPS="all/${KERNELBRANCHLET}/apply/$dep $NEEDED_DEPS"
    elif [ -x ${TOPPATCHDIR}/${ARCHITECTURE}/apply/$dep ]
    then
        NEEDED_DEPS="${ARCHITECTURE}/apply/$dep $NEEDED_DEPS"
    elif [ -x ${TOPPATCHDIR}/all/apply/$dep ]
    then
        NEEDED_DEPS="all/apply/$dep $NEEDED_DEPS"
    else
        echo >&2 "ERROR: Patch dependency \`$dep' not found - aborting"
        echo >&2 "END applying grsecurity2 patch"
        exit 1
    fi
done
if [ "$NEEDED_DEPS" ]
then
    echo >&2 "Ensuring the following patches are applied first: $NEEDED_DEPS"
    for apply in ${NEEDED_DEPS}
    do
        dep=$(basename $apply)
        ${TOPPATCHDIR}/$apply

        # check something was applied
        if [ ! -f debian/APPLIED_${ARCHITECTURE}_$dep -a \
             ! -f debian/APPLIED_all_$dep ]
        then
            echo >&2 "ERROR: patch dependency did not left a patch stamp (version mismatch ?) - aborting"
            echo >&2 "END applying grsecurity2 patch"
            exit 1
        fi
    done
    UNPATCHDEPS=$(echo ${NEEDED_DEPS} | sed s,/apply/,/unpatch/,g)
fi

echo >&2 "Testing whether \"Greater Security for Linux 2.6 and 3.x\" patch for $KVERSION applies (dry run):"
if ! [ -r $PATCHFILE ]
then
    echo >&2 "\"Greater Security for Linux 2.6 and 3.x\" patch for $KVERSION not found"
    exit 1
elif ! $DECOMPRESSOR $PATCHFILE |
        patch --force --dry-run $PATCH_OPTIONS -p$STRIPLEVEL
then
    echo >&2 "\"Greater Security for Linux 2.6 and 3.x\" patch for $KVERSION does not apply cleanly"
    exit 1
fi
if ! $DECOMPRESSOR $PATCHFILE |
        patch $PATCH_OPTIONS -p$STRIPLEVEL
then
    # This should never happen, thanks to the dry-run
    echo >&2 "ASSERTION FAILED - \"Greater Security for Linux 2.6 and 3.x\" patch for $KVERSION failed"
    echo >&2 "END applying grsecurity2 patch"
    exit 1
fi
echo >&2 "\"Greater Security for Linux 2.6 and 3.x\" patch for $KVERSION succeeded"

echo >&2 "Removing empty files:"
# make an exception for ./debian, or else the stamp files will go too.
find . -path ./debian -prune -o \
       -type f -size 0 ! -name 'APPLIED*' -exec rm {} \; -print
echo >&2 "Done."

mkdir -p debian
cat > 'debian/APPLIED_all_grsecurity2' <<EOF
PATCHFILE='$PATCHFILE'
STRIPLEVEL='$STRIPLEVEL'
DEPENDS='$UNPATCHDEPS'
EOF
mkdir -p debian/image.d
PKGNAME=`dpkg -S $PATCHFILE | cut -d: -f1`
PKGVERS=`grep-dctrl -n -P $PKGNAME -s Version -X /var/lib/dpkg/status`
cat > 'debian/image.d/register-grsecurity2' <<EOF
#!/bin/sh

# This scripts documents the "Greater Security for Linux 2.6 and 3.x" kernel patch into the
# kernel-image package, as being applied to the kernel.

docdir=\${IMAGE_TOP}/usr/share/doc/kernel-image-\${version}

mkdir -p \${docdir}

(
    printf 'Greater Security for Linux 2.6 and 3.x (grsecurity2)${KPATCH_grsecurity2:+ for kernel ${KPATCH_grsecurity2}},'
    echo ' from package $PKGNAME, version $PKGVERS'
) >> \${docdir}/applied-patches
EOF
chmod +x 'debian/image.d/register-grsecurity2'

echo >&2 "END applying grsecurity2 patch"
