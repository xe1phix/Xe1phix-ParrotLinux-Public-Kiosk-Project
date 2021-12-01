

curl https://getfedora.org/static/fedora.gpg | gpg --import

gpg: key 812A6B4B64DAB85D: public key "Fedora 26 Primary (26) <fedora-26-primary@fedoraproject.org>" imported
gpg: key 4560FD4D3B921D09: public key "Fedora 26 Secondary (26) <fedora-26-secondary@fedoraproject.org>" imported
gpg: key F55E7430F5282EE4: public key "Fedora 27 (27) <fedora-27@fedoraproject.org>" imported
gpg: key E08E7E629DB62FB1: public key "Fedora 28 (28) <fedora-28@fedoraproject.org>" imported
gpg: key A20AA56B429476B4: public key "Fedora 29 (29) <fedora-29@fedoraproject.org>" imported
gpg: key 3B49DF2A0608B895: public key "EPEL (6) <epel@fedoraproject.org>" imported
gpg: key 6A2FAEA2352C64E5: public key "Fedora EPEL (7) <epel@fedoraproject.org>" imported



gpg --verbose --keyserver hkps.pool.sks-keyservers.net --receive-key 0x128CF232A9371991C8A65695E08E7E629DB62FB1

gpg --verbose --keyserver hkps.pool.sks-keyservers.net --recv-keys 0x128CF232A9371991C8A65695E08E7E629DB62FB1


gpg --fingerprint 0x128CF232A9371991C8A65695E08E7E629DB62FB1

                128C F232 A937 1991 C8A6  5695 E08E 7E62 9DB6 2FB1
Fingerprint 	128C F232 A937 1991 C8A6  5695 E08E 7E62 9DB6 2FB1
Primary key fingerprint: 128C F232 A937 1991 C8A6  5695 E08E 7E62 9DB6 2FB1
                         128C F232 A937 1991 C8A6  5695 E08E 7E62 9DB6 2FB1

gpg --lsign 0x128CF232A9371991C8A65695E08E7E629DB62FB1



gpg --verify-files *-CHECKSUM


The CHECKSUM file should have a good signature from one of the following keys:

429476B4 - Fedora 29
9DB62FB1 - Fedora 28
F5282EE4 - Fedora 27
64DAB85D - Fedora 26
3B921D09 - Fedora 26 secondary arches (AArch64, PPC64, PPC64le, s390 and s390x)



https://getfedora.org/en/keys/

Key ID 	4096R/429476B4 2018-02-17
Fingerprint 	5A03 B4DD 8254 ECA0 2FDA  1637 A20A A56B 4294 76B4
uid 	Fedora 29 (29) <fedora-29@fedoraproject.org>



Key ID 	4096R/9DB62FB1 2017-08-14
Fingerprint 	128C F232 A937 1991 C8A6  5695 E08E 7E62 9DB6 2FB1
uid 	Fedora 28 (28) <fedora-28@fedoraproject.org>


Key ID 	4096R/F5282EE4 2017-02-21
Fingerprint 	860E 19B0 AFA8 00A1 7518  81A6 F55E 7430 F528 2EE4
uid 	Fedora 27 (27) <fedora-27@fedoraproject.org>

Key ID 	4096R/64DAB85D 2016-09-09
Fingerprint 	E641 850B 77DF 4353 78D1  D7E2 812A 6B4B 64DA B85D
uid 	Fedora 26 Primary (26) <fedora-26-primary@fedoraproject.org>


Key ID 	4096R/352C64E5 2013-12-16
Fingerprint 	91E9 7D7C 4A5E 96F1 7F3E  888F 6A2F AEA2 352C 64E5
uid 	Fedora EPEL (7) <epel@fedoraproject.org>









# Fedora-Security-Live-x86_64-28-1.1.iso: 1470103552 bytes
SHA256 (Fedora-Security-Live-x86_64-28-1.1.iso) = d2e11f9eeb4eae69db61c3d36f1ce063d45d9ab4a29827f3a0b77547039f382f


sha256sum Fedora-Security-Live-x86_64-28-1.1.iso
d2e11f9eeb4eae69db61c3d36f1ce063d45d9ab4a29827f3a0b77547039f382f  Fedora-Security-Live-x86_64-28-1.1.iso
d2e11f9eeb4eae69db61c3d36f1ce063d45d9ab4a29827f3a0b77547039f382f




sha256sum Fedora-AtomicWorkstation-ostree-x86_64-28-1.1.iso 
3c57cef9cc85e73d6ecac1f7ebdb84cd9b6f2420da0667b112ce8cf20c5404b6  Fedora-AtomicWorkstation-ostree-x86_64-28-1.1.iso
3c57cef9cc85e73d6ecac1f7ebdb84cd9b6f2420da0667b112ce8cf20c5404b6



















