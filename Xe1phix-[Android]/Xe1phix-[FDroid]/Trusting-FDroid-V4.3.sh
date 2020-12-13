




gpg --full-gen-key

Requested keysize is 4096 bits

Key is valid for? 7m

 list the private GPG key you just created:
gpg --list-secret-keys --keyid-format LONG mr@robot.sh

Export the public key of that ID (replace your key ID from the previous step):
gpg --armor --export 30F2B65B9246B6CA




Adding a GPG key to your account

copy the public key and add it in your profile settings
https://gitlab.com/help/user/project/repository/gpg_signed_commits/index.md#adding-a-gpg-key-to-your-account


Navigate to the GPG keys tab and paste your public key in the 'Key' box.




Associating your GPG key with Git

After you have created your GPG key and added it to your account,


list the private GPG key you just created:

gpg --list-secret-keys --keyid-format LONG mr@robot.sh



use your GnuPG fingerprint to sign the commits:
git config --global user.signingkey 




start signing your commits:


Push to GitLab and check that your commits are verified.
git commit -S -m "My commit msg"


tell Git to sign your commits automatically:
git config --global commit.gpgsign true








Create a backup of your .gnupg dir.
$ umask 077; tar -cf $HOME/gnupg-backup.tar -C $HOME .gnupg


sec => 'SECret key'
ssb => 'Secret SuBkey'
pub => 'PUBlic key'
sub => 'public SUBkey'


Constant           Character      Explanation
─────────────────────────────────────────────────────
PUBKEY_USAGE_SIG      S       key is good for signing
PUBKEY_USAGE_CERT     C       key is good for certifying other signatures
PUBKEY_USAGE_ENC      E       key is good for encryption
PUBKEY_USAGE_AUTH     A       key is good for authentication





gpg --edit-key 0x
adduid
uid 2

 (E flag)is a separate subkey for encryption.
primary

save



Add new signing subkey

gpg --edit-key 0x
addkey

(3) DSA (sign only)
(4) RSA (sign only)
(5) Elgamal (encrypt only)
(6) RSA (encrypt only)

Your selection? 4

keysize do you want? (2048) 4096

Key is valid for?  7m

save


create a revocation certificate:
gpg --output 0x6F87F32E2234961E.gpg-revocation-certificate --armor --gen-revoke 0x6F87F32E2234961E


Create a revocation certificate for this key? (y/N) y

Enter an optional description; end it with an empty line:

> This revocation certificate was generated when the key was created


Is this okay? (y/N) y 




Remove Master key
And now the interesting part, 
it’s time to remove the master key from your laptops’s keychain 
and just leave the subkeys. 

You will store the master key in the encrypted usb so it stays safe.


cp -v -R $HOME/.gnupg /media/$USB
                or
rsync -avp $HOME/.gnupg /media/$USB




umask 077; tar -cf /media/encrypted-usb/gnupg-backup-new.tar -C $HOME .gnupg


time to remove the master key!

$ gpg --export-secret-subkeys 0x6F87F32E2234961E > /media/encrypted-usb/subkeys
$ gpg --delete-secret-key 0x6F87F32E2234961E
$ gpg --import /media/encrypted-usb/subkeys
$ shred -u /media/encrypted-usb/subkeys

[+] exported the subkeys to encrypted-usb
[+] delete the master key
[+] re-import just the subkeys. 



The only place you have a Master key is only on the encrypted USB key now.




Notice the pound (#) in the ‘sec’ line from your ~/.gnupg/. That means that the master key is missing.


gpg -K 0x6F87F32E2234961E                                             
sec#   4096R/0x6F87F32E2234961E 2013-12-01

gpg --home=/media/encrypted-usb/.gnupg/ -K 0x6F87F32E2234961E                                             
sec   4096R/0x6F87F32E2234961E 2013-12-01


when you migrate from an older key, to a new one,
you need to sign your new key with the old one 


gpg --default-key 0x

sign it with both the old and the new key:



$ gpg --armor -b -u 0xOLD_KEY -o sig1.txt gpg-transition.txt
$ gpg --armor -b -u 0x6F87F32E2234961E -o sig2.txt gpg-transition.txt


Signing other people’s keys
Because your laptop’s keypair does not have the master key anymore and the master key is the only one with the ‘C’ flag, when you want to sign someone else’s key, you will need to mount your encrypted USB and then issue a command that’s using that encrypted directory:
$ gpg --home=/media/encrypted-usb/.gnupg/ --sign-key 0xSomeones_keyid

Export your signature and send it back to people whose key you just signed..





https://www.void.gr/kargig/blog/2013/12/02/creating-a-new-gpg-key-with-subkeys/

















## 




## 
https://gitlab.com/help/user/project/repository/gpg_signed_commits/index.md#verifying-commits

## Managing OpenPGP Keys
https://riseup.net/en/security/message-security/openpgp/gpg-keys

## keyserver poo
https://sks-keyservers.net/overview-of-pools.php



## download the sks-keyservers.net CA
https://sks-keyservers.net/sks-keyservers.netCA.pem


## verify the certificate’s finger print.
https://sks-keyservers.net/verify_tls.php


## saved the .pem file above:
~/.gnupg/gpg.conf


keyserver hkps://hkps.pool.sks-keyservers.net
keyserver-options ca-cert-file=/path/to/CA/sks-keyservers.netCA.pem









## 



Release Channels and Signing Keys

This is a list of all signing keys used for F-Droid releases.
F-Droid client app for Android

            [+] Git Repo: 
https://gitlab.com/fdroid/fdroidclient
            
            [+] git tags signed by 
“Hans-Christoph Steiner <hans@guardianproject.info>”
“Hans-Christoph Steiner <hans@eds.org>”
“Hans-Christoph Steiner <hans@at.or.at>” 


            [+] fingerprint:
EE66 20C7 136B 0D2C 456C 0A4D E9E2 8DEA 00AA 5556

    [+] signed by “Daniel Martí <mvdan@mvdan.cc>”
“Daniel Martí <mvdan@fsfe.org>” 

            [+] fingerprint:
A9DA 13CD F7A1 4ACD D3DE E530 F4CA FFDB 4348 041C

[+] Offical  binary releases: 
https://f-droid.org/repository/browse/?fdfilter=f-droid&fdid=org.fdroid.fdroid

GPG signing key: “F-Droid <admin@f-droid.org>”
Primary key fingerprint: 37D2 C987 89D8 3119 4839 4E3E 41E7 044E 1DBA 2E89
Subkey fingerprint: 802A 9799 0161 1234 6E1F EFF4 7A02 9E54 DD5D CE7A


                         [+] APK signing key:

Owner: CN=Ciaran Gultnieks, OU=Unknown, O=Unknown, L=Wetherby, ST=Unknown, C=UK
Issuer: CN=Ciaran Gultnieks, OU=Unknown, O=Unknown, L=Wetherby, ST=Unknown, C=UK
Serial number: 4c49cd00


                     [+] Valid from: 
                Fri Jul 23 13:10:24 EDT 2010 

                     [+] Valid Until: 
               Tue Dec 08 12:10:24 EST 2037



____________[+] Certificate fingerprints:___________
MD5:  17:C5:5C:62:80:56:E1:93:E9:56:44:E9:89:79:27:86
SHA1: 05:F2:E6:59:28:08:89:81:B3:17:FC:9A:6D:BF:E0:4B:0F:A1:3B:4E
SHA256: 43:23:8D:51:2C:1E:5E:B2:D6:56:9F:4A:3A:FB:F5:52:34:18:B8:2E:0A:3E:D1:55:27:70:AB:B9:A9:C9:CC:AB




__[+] The whole certificate:______

-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAltB15HwBTngiyJ/Wf3ld
IyA+KohD9Tuk5rG/Xy/Q4iWTgmfPyuf79P5ZY0avuvQHD9uR9m+83yNIo9kkMFAo
JPgFF7FW+rAICb3I5jG/qa/ULZBFq1/W0o2eFAr8EwCRexm3xsTfSklM8ffLSmPI
DXNCZdc1r55PCUVfQnqmWlNWP4ezNsosGdJE/LumF7oLGeVu00r+CyU6uR4v2xJx
8bnjwyMgJ+2IYqES8HBuI0zyNpFLk5vPlZgh7LKmwYBX4HDeNCgEbZSxdeHYm9eV
5TVJmgkfW8ZaedU5qNQ4kexQQFissowIOTtXGLV2AKIR6AP0pjTlxX8lubjEQixv
2QIDAQAB
-----END PUBLIC KEY-----




-----BEGIN CERTIFICATE-----
MIIDXjCCAkagAwIBAgIETEnNADANBgkqhkiG9w0BAQUFADBxMQswCQYDVQQGEwJV
SzEQMA4GA1UECBMHVW5rbm93bjERMA8GA1UEBxMIV2V0aGVyYnkxEDAOBgNVBAoT
B1Vua25vd24xEDAOBgNVBAsTB1Vua25vd24xGTAXBgNVBAMTEENpYXJhbiBHdWx0
bmlla3MwHhcNMTAwNzIzMTcxMDI0WhcNMzcxMjA4MTcxMDI0WjBxMQswCQYDVQQG
EwJVSzEQMA4GA1UECBMHVW5rbm93bjERMA8GA1UEBxMIV2V0aGVyYnkxEDAOBgNV
BAoTB1Vua25vd24xEDAOBgNVBAsTB1Vua25vd24xGTAXBgNVBAMTEENpYXJhbiBH
dWx0bmlla3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCW0HXkfAFO
eCLIn9Z/eV0jID4qiEP1O6Tmsb9fL9DiJZOCZ8/K5/v0/lljRq+69AcP25H2b7zf
I0ij2SQwUCgk+AUXsVb6sAgJvcjmMb+pr9QtkEWrX9bSjZ4UCvwTAJF7GbfGxN9K
SUzx98tKY8gNc0Jl1zWvnk8JRV9CeqZaU1Y/h7M2yiwZ0kT8u6YXugsZ5W7TSv4L
JTq5Hi/bEnHxuePDIyAn7YhioRLwcG4jTPI2kUuTm8+VmCHssqbBgFfgcN40KARt
lLF14dib15XlNUmaCR9bxlp51Tmo1DiR7FBAWKyyjAg5O1cYtXYAohHoA/SmNOXF
fyW5uMRCLG/ZAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAAjk72memAdnf/VnU9pz
77I5DVriwX5NtpHV33p7YPwHGuUJxUFL59XadN8oEeg9NmjEoLGryEufp9lrTN8w
u6aFF60qk+IzsEKXKsBVOkgByevge/V+vpo7PW1mOWUmDlDzuPRtsFMXYeYDQKK9
3DQmCYOX/aVARKF+UkRUn5hptGDKXm4ha29qLbBYC0gMoq/m7GtG7trPpKpFA4gJ
7ODFl4ZT1shfZ45/WiFW0b7dgRd1HmSksNzRQPMECwIYIajZOu2NAbo222yCNyIR
/tcU2aMmBwOM39VlvVKf/GNyEqqiwiTvIrYD7M77W/HghcGR1LJP50KxerP1XU5v
Be8=
-----END CERTIFICATE-----




              [+] Fdroid Server

[+] Git Repo: https://gitlab.com/fdroid/fdroidserver

            [+] Git tags signed by 
“Hans-Christoph Steiner <hans@guardianproject.info>”
“Hans-Christoph Steiner <hans@eds.org>”
“Hans-Christoph Steiner <hans@at.or.at>”

            [+] Fingerprint:
EE66 20C7 136B 0D2C 456C 0A4D E9E2 8DEA 00AA 5556



[+] Package tags signed by with fingerprint:
“Daniel Martí <mvdan@mvdan.cc>”
“Daniel Martí <mvdan@fsfe.org>”

             [+] Fingerprint:
A9DA 13CD F7A1 4ACD D3DE E530 F4CA FFDB 4348 041C




  [+] source Package signed by with fingerprint:: 
https://pypi.python.org/pypi/fdroidserver

         [+] Package tags signed by 
“Hans-Christoph Steiner <hans@guardianproject.info>” 
“Hans-Christoph Steiner <hans@eds.org>” 
“Hans-Christoph Steiner <hans@at.or.at>”

EE66 20C7 136B 0D2C 456C 0A4D E9E2 8DEA 00AA 5556 or previously
5E61 C878 0F86 295C E17D 8677 9F0F E587 374B BE81

     [+] Release command: 
python3 setup.py sdist upload --sign

     [+] Offical  Debian Package: 
https://Packages.debian.org/fdroidserver

                 [+] Package source: 
https://anonscm.debian.org/git/collab-maint/fdroidserver.git



    [+] Package tags signed by with fingerprint:
     
“Hans-Christoph Steiner <hans@guardianproject.info>”
“Hans-Christoph Steiner <hans@eds.org>” 
“Hans-Christoph Steiner <hans@at.or.at>” 
        

EE66 20C7 136B 0D2C 456C 0A4D E9E2 8DEA 00AA 5556 or previously
5E61 C878 0F86 295C E17D 8677 9F0F E587 374B BE81

                [+] Offical  Ubuntu PPA: 
https://launchpad.net/~fdroid/+archive/ubuntu/fdroidserver

fingerprint: 9AAC 2531 93B6 5D4D F1D0 A13E EC46 32C7 9C5E 0151


        [+] How to setup:
sudo add-apt-repository ppa:fdroid/fdroidserver
sudo apt-get update
sudo apt-get install fdroidserver

        [+] Privileged Extension

     [+] Git Repo (git tags signed by):
https://gitlab.com/fdroid/privileged-extension

  [+] Package tags signed by with fingerprint:
“Hans-Christoph Steiner <hans@guardianproject.info>” 
“Hans-Christoph Steiner <hans@eds.org>” 
“Hans-Christoph Steiner <hans@at.or.at>” 

EE66 20C7 136B 0D2C 456C 0A4D E9E2 8DEA 00AA 5556











## ------------------------------------------------------------------------------------------------------------------------------------------ ##
## gpg --verbose --keyid-format 0xlong --keyserver hkp://pool.sks-keyservers.net --recv-keys 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
## gpg --verbose --keyid-format 0xlong --import FDroid.asc
## gpg --verbose --keyid-format 0xlong --import f-droid.org-signing-key.gpg
## gpg --verbose --keyid-format 0xlong --import public.asc
## ------------------------------------------------------------------------------------------------------------------------------------------ ##
## gpg --fingerprint --with-subkey-fingerprint 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
## ------------------------------------------------------------------------------------------------------------------------------------------ ##
## gpg --edit-key 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
## gpg --keyid-format 0xlong --verbose --lsign 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
## ------------------------------------------------------------------------------------------------------------------------------------------ ##



echo "[+]=====================================================================[+]"
FDroidPlayStore="https://microg.org/fdroid/repo"
FDroidPlayStoreArchive="https://microg.org/fdroid/repo"
SignalTextSecureBuilds="https://microg.org/fdroid/archive"
echo "[+]=====================================================================[+]"
FDroidMainRepo="https://f-droid.org/repo"
echo "[+]=====================================================================[+]"
GuardianProjectMainRepo="https://guardianproject.info/fdroid/repo"
export GuardianProjectMainRepo="https://guardianproject.info/fdroid/repo"
echo "[+]=====================================================================[+]"
GuardianProjectAWS="https://s3.amazonaws.com/guardianproject/fdroid/repo"
export GuardianProjectAWS="https://s3.amazonaws.com/guardianproject/fdroid/repo"
echo "[+]=====================================================================[+]"
TorHiddenServiceFDroidRepo="http://bdf2wcxujkg6qqff.onion/fdroid/repo"
export TorHiddenServiceFDroidRepo="http://bdf2wcxujkg6qqff.onion/fdroid/repo"
echo "[+]=====================================================================[+]"
FDroidIOFrontend="https://f-droid.i2p.io/repo/"
export FDroidIOFrontend="https://f-droid.i2p.io/repo/"
echo "[+]=====================================================================[+]"
F-DroidArchive="https://f-droid.org/archive"
export F-DroidArchive="https://f-droid.org/archive"
echo "[+]=====================================================================[+]"
FDroidClientGitRepo="https://gitlab.com/fdroid/fdroidclient"
export FDroidClientGitRepo="https://gitlab.com/fdroid/fdroidclient"
echo "[+]=====================================================================[+]"
GPG signing key: "F-Droid <admin@f-droid.org>" 
FDroidGPGFpr="37D2 C987 89D8 3119 4839 4E3E 41E7 044E 1DBA 2E89"
FDroidGPGSubkeyFpr="802A 9799 0161 1234 6E1F EFF4 7A02 9E54 DD5D CE7A"
echo "[+]==================================================================================================[+]"
## git tags signed by "Daniel Martí <mvdan@mvdan.cc>" aka "Daniel Martí <mvdan@fsfe.org>" 
## with fingerprint: 
FDroidGitFpr="A9DA 13CD F7A1 4ACD D3DE E530 F4CA FFDB 4348 041C"
echo "[+]==================================================================================================[+]"
FDroidAPKSigningKey=""
echo "## Certificate fingerprints:
echo "##   MD5:  17:C5:5C:62:80:56:E1:93:E9:56:44:E9:89:79:27:86
echo "##   SHA1: 05:F2:E6:59:28:08:89:81:B3:17:FC:9A:6D:BF:E0:4B:0F:A1:3B:4E
echo "##   SHA256: 43:23:8D:51:2C:1E:5E:B2:D6:56:9F:4A:3A:FB:F5:52:34:18:B8:2E:0A:3E:D1:55:27:70:AB:B9:A9:C9:CC:AB
echo "[+]==================================================================================================[+]"








fdroid import --url=http://address.of.project



GitLab - https://gitlab.com/<PROJECTNAME>/<REPONAME>
Github - https://github.com/<USER>/<PROJECT>
Bitbucket - https://bitbucket.org/<USER>/<PROJECT>/
Git - git://<REPO> or https://<REPO>


-u <URL>, --url=<URL>: Project URL to import from.
-s <DIR>, --subdir=<DIR>: Path to main android project subdirectory,
-c <CATEGORIES>, --categories=<CATEGORIES>: Comma separated list of categories.







https://gitlab.com/fdroid/artwork/raw/master/badge/get-it-on.png


    https://guardianproject.info/fdroid/
    https://microg.org/fdroid.html
    https://grobox.de/fdroid/
    https://fdroid.eutopia.cz/






 check repo index timestamps to prevent rollback attacks 




sends the preload directive in an HSTS header,
HTTP Strict Transport Security (HSTS) preload list. 
https://hstspreload.org/?domain=f-droid.org



https://www.ssllabs.com/ssltest/analyze?d=f-droid.org

https://tls-observatory.services.mozilla.com/static/certsplainer.html?id=186454241



observatory.mozilla.org/

 securityheaders.com 
https://securityheaders.com/?followRedirects=on&hide=on&q=f-droid.org

 hstspreload.org 
 	https://hstspreload.org/?domain=f-droid.org


https://debian-administration.org/users/dkg/weblog/106

Signing Your Work
https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work


https://riseup.net/en/security/message-security/openpgp/best-practices

https://f-droid.org/en/docs/

https://f-droid.org/FDroid.apk
https://f-droid.org/FDroid.apk.asc


http://www.devops-blog.net/koji/gpg-signing-rpms-with-sigul-signing-server-koji-integration

https://fedorahosted.org/sigul/

https://webchat.freenode.net/?channels=%23fdroid



















    Cipher Suites



___ Cipher suite _________________ Code ____ Key size ___________ AEAD ___ PFS __ Protocols ___
1.	ECDHE-RSA-AES128-GCM-SHA256	0x0C,0x2F	2048 bits			TLS 1.2
2.	DHE-RSA-AES128-GCM-SHA256	0x00,0x9E	2048 bits			TLS 1.2
3.	ECDHE-RSA-AES128-SHA256	    0x0C,0x27	2048 bits			TLS 1.2
4.	ECDHE-RSA-AES128-SHA	    0x0C,0x13	2048 bits			TLS 1.2, TLS 1.1, TLS 1.0
5.	DHE-RSA-AES128-SHA256	    0x00,0x67	2048 bits			TLS 1.2
6.	DHE-RSA-AES128-SHA	        0x00,0x33	2048 bits			TLS 1.2, TLS 1.1, TLS 1.0
7.	DHE-RSA-CAMELLIA128-SHA	    0x00,0x45	2048 bits			TLS 1.2, TLS 1.1, TLS 1.0
8.	RSA-AES128-GCM-SHA256	    0x00,0x9C	2048 bits			TLS 1.2
9.	RSA-AES128-SHA256	        0x00,0x3C	2048 bits			TLS 1.2
10.	RSA-AES128-SHA	            0x00,0x2F	2048 bits			TLS 1.2, TLS 1.1, TLS 1.0
11.	RSA-CAMELLIA128-SHA	        0x00,0x41	2048 bits			TLS 1.2, TLS 1.1, TLS 1.0
12.	RSA-DES-CBC3-SHA	        0x00,0x0A	2048 bits			TLS 1.2, TLS 1.1, TLS 1.0



     Ciphersuites: ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
    Versions: TLSv1.2
    TLS curves: prime256v1, secp384r1, secp521r1
    Certificate type: ECDSA
    Certificate curve: prime256v1, secp384r1, secp521r1
    Certificate signature: sha256WithRSAEncryption, ecdsa-with-SHA256, ecdsa-with-SHA384, ecdsa-with-SHA512
    RSA key size: 2048 (if not ecdsa)
    DH Parameter size: None (disabled entirely)
    ECDH Parameter size: 256
    HSTS: max-age=15768000
    Certificate switching: None

0xC0,0x2C  -  ECDHE-ECDSA-AES256-GCM-SHA384  TLSv1.2  Kx=ECDH  Au=ECDSA  Enc=AESGCM(256)    Mac=AEAD
0xC0,0x30  -  ECDHE-RSA-AES256-GCM-SHA384    TLSv1.2  Kx=ECDH  Au=RSA    Enc=AESGCM(256)    Mac=AEAD
0xCC,0xA9  -  ECDHE-ECDSA-CHACHA20-POLY1305  TLSv1.2  Kx=ECDH  Au=ECDSA  Enc=ChaCha20(256)  Mac=AEAD
0xCC,0xA8  -  ECDHE-RSA-CHACHA20-POLY1305    TLSv1.2  Kx=ECDH  Au=RSA    Enc=ChaCha20(256)  Mac=AEAD
0xC0,0x2B  -  ECDHE-ECDSA-AES128-GCM-SHA256  TLSv1.2  Kx=ECDH  Au=ECDSA  Enc=AESGCM(128)    Mac=AEAD
0xC0,0x2F  -  ECDHE-RSA-AES128-GCM-SHA256    TLSv1.2  Kx=ECDH  Au=RSA    Enc=AESGCM(128)    Mac=AEAD
0xC0,0x24  -  ECDHE-ECDSA-AES256-SHA384      TLSv1.2  Kx=ECDH  Au=ECDSA  Enc=AES(256)       Mac=SHA384
0xC0,0x28  -  ECDHE-RSA-AES256-SHA384        TLSv1.2  Kx=ECDH  Au=RSA    Enc=AES(256)       Mac=SHA384
0xC0,0x23  -  ECDHE-ECDSA-AES128-SHA256      TLSv1.2  Kx=ECDH  Au=ECDSA  Enc=AES(128)       Mac=SHA256
0xC0,0x27  -  ECDHE-RSA-AES128-SHA256        TLSv1.2  Kx=ECDH  Au=RSA    Enc=AES(128)       Mac=SHA256

Rationale:

    AES256-GCM is prioritized above its 128 bits variant, and ChaCha20 because we assume that most modern devices support AESNI instructions and thus benefit from fast and constant time AES.
    We recommend ECDSA certificates with P256 as other curves may not be supported everywhere. RSA signatures on ECDSA certificates are permitted because very few CAs sign with ECDSA at the moment.
    DHE is removed entirely because it is slow in comparison with ECDHE, and all modern clients support elliptic curve key exchanges.
    SHA1 signature algorithm is removed in favor of SHA384 for AES256 and SHA256 for AES128.











     <?xml version="1.0" encoding="utf-8"?>
<resources>

    <!-- 1 - https://f-droid.org/repo -->
    <string name="fdroid_repo_name" formatted="false" translatable="false">F-Droid</string>

    <integer name="fdroid_repo_version">13</integer>
    <integer name="fdroid_repo_inuse">1</integer>
    <integer name="fdroid_repo_priority">10</integer>

    <string name="fdroid_repo_address" formatted="false" translatable="false">https://f-droid.org/repo</string>
    <string name="fdroid_repo_description" formatted="false" translatable="false">The official F-Droid repository. Applications in this repository are mostly built directory from the source code. Some are official binaries built by the original application developers - these will be replaced by source-built versions over time.</string>
    <string name="fdroid_repo_pubkey" formatted="false" translatable="false">3082035e30820246a00302010202044c49cd00300d06092a864886f70d01010505003071310b300906035504061302554b3110300e06035504081307556e6b6e6f776e3111300f0603550407130857657468657262793110300e060355040a1307556e6b6e6f776e3110300e060355040b1307556e6b6e6f776e311930170603550403131043696172616e2047756c746e69656b73301e170d3130303732333137313032345a170d3337313230383137313032345a3071310b300906035504061302554b3110300e06035504081307556e6b6e6f776e3111300f0603550407130857657468657262793110300e060355040a1307556e6b6e6f776e3110300e060355040b1307556e6b6e6f776e311930170603550403131043696172616e2047756c746e69656b7330820122300d06092a864886f70d01010105000382010f003082010a028201010096d075e47c014e7822c89fd67f795d23203e2a8843f53ba4e6b1bf5f2fd0e225938267cfcae7fbf4fe596346afbaf4070fdb91f66fbcdf2348a3d92430502824f80517b156fab00809bdc8e631bfa9afd42d9045ab5fd6d28d9e140afc1300917b19b7c6c4df4a494cf1f7cb4a63c80d734265d735af9e4f09455f427aa65a53563f87b336ca2c19d244fcbba617ba0b19e56ed34afe0b253ab91e2fdb1271f1b9e3c3232027ed8862a112f0706e234cf236914b939bcf959821ecb2a6c18057e070de3428046d94b175e1d89bd795e535499a091f5bc65a79d539a8d43891ec504058acb28c08393b5718b57600a211e803f4a634e5c57f25b9b8c4422c6fd90203010001300d06092a864886f70d0101050500038201010008e4ef699e9807677ff56753da73efb2390d5ae2c17e4db691d5df7a7b60fc071ae509c5414be7d5da74df2811e83d3668c4a0b1abc84b9fa7d96b4cdf30bba68517ad2a93e233b042972ac0553a4801c9ebe07bf57ebe9a3b3d6d663965260e50f3b8f46db0531761e60340a2bddc3426098397fda54044a17e5244549f9869b460ca5e6e216b6f6a2db0580b480ca2afe6ec6b46eedacfa4aa45038809ece0c5978653d6c85f678e7f5a2156d1bedd8117751e64a4b0dcd140f3040b021821a8d93aed8d01ba36db6c82372211fed714d9a32607038cdfd565bd529ffc637212aaa2c224ef22b603eccefb5bf1e085c191d4b24fe742b17ab3f55d4e6f05ef</string>

    <!-- 2 - https://f-droid.org/archive -->
    <string name="fdroid_archive_name" formatted="false" translatable="false">F-Droid Archive</string>

    <integer name="fdroid_archive_version">13</integer>
    <integer name="fdroid_archive_inuse">0</integer>
    <integer name="fdroid_archive_priority">20</integer>

    <string name="fdroid_archive_address" formatted="false" translatable="false">https://f-droid.org/archive</string>
    <string name="fdroid_archive_description" formatted="false" translatable="false">The archive repository of the F-Droid client. This contains older versions of applications from the main repository.</string>
    <string name="fdroid_archive_pubkey" formatted="false" translatable="false">3082035e30820246a00302010202044c49cd00300d06092a864886f70d01010505003071310b300906035504061302554b3110300e06035504081307556e6b6e6f776e3111300f0603550407130857657468657262793110300e060355040a1307556e6b6e6f776e3110300e060355040b1307556e6b6e6f776e311930170603550403131043696172616e2047756c746e69656b73301e170d3130303732333137313032345a170d3337313230383137313032345a3071310b300906035504061302554b3110300e06035504081307556e6b6e6f776e3111300f0603550407130857657468657262793110300e060355040a1307556e6b6e6f776e3110300e060355040b1307556e6b6e6f776e311930170603550403131043696172616e2047756c746e69656b7330820122300d06092a864886f70d01010105000382010f003082010a028201010096d075e47c014e7822c89fd67f795d23203e2a8843f53ba4e6b1bf5f2fd0e225938267cfcae7fbf4fe596346afbaf4070fdb91f66fbcdf2348a3d92430502824f80517b156fab00809bdc8e631bfa9afd42d9045ab5fd6d28d9e140afc1300917b19b7c6c4df4a494cf1f7cb4a63c80d734265d735af9e4f09455f427aa65a53563f87b336ca2c19d244fcbba617ba0b19e56ed34afe0b253ab91e2fdb1271f1b9e3c3232027ed8862a112f0706e234cf236914b939bcf959821ecb2a6c18057e070de3428046d94b175e1d89bd795e535499a091f5bc65a79d539a8d43891ec504058acb28c08393b5718b57600a211e803f4a634e5c57f25b9b8c4422c6fd90203010001300d06092a864886f70d0101050500038201010008e4ef699e9807677ff56753da73efb2390d5ae2c17e4db691d5df7a7b60fc071ae509c5414be7d5da74df2811e83d3668c4a0b1abc84b9fa7d96b4cdf30bba68517ad2a93e233b042972ac0553a4801c9ebe07bf57ebe9a3b3d6d663965260e50f3b8f46db0531761e60340a2bddc3426098397fda54044a17e5244549f9869b460ca5e6e216b6f6a2db0580b480ca2afe6ec6b46eedacfa4aa45038809ece0c5978653d6c85f678e7f5a2156d1bedd8117751e64a4b0dcd140f3040b021821a8d93aed8d01ba36db6c82372211fed714d9a32607038cdfd565bd529ffc637212aaa2c224ef22b603eccefb5bf1e085c191d4b24fe742b17ab3f55d4e6f05ef</string>

    <!-- https://guardianproject.info/fdroid/repo -->
    <string name="guardianproject_repo_name" formatted="false" translatable="false">Guardian Project</string>

    <integer name="guardianproject_repo_version">13</integer>
    <integer name="guardianproject_repo_inuse">0</integer>
    <integer name="guardianproject_repo_priority">10</integer>

    <string name="guardianproject_repo_address" formatted="false" translatable="false">https://guardianproject.info/fdroid/repo</string>
    <string name="guardianproject_repo_description" formatted="false" translatable="false">The official app repository of The Guardian Project.  Applications in this repository are official binaries build by the original application developers and signed by the same key as the APKs that are released in the Google Play store.</string>
    <string name="guardianproject_repo_pubkey" formatted="false" translatable="false">308205d8308203c0020900a397b4da7ecda034300d06092a864886f70d01010505003081ad310b30090603550406130255533111300f06035504080c084e657720596f726b3111300f06035504070c084e657720596f726b31143012060355040b0c0b4644726f6964205265706f31193017060355040a0c10477561726469616e2050726f6a656374311d301b06035504030c14677561726469616e70726f6a6563742e696e666f3128302606092a864886f70d0109011619726f6f7440677561726469616e70726f6a6563742e696e666f301e170d3134303632363139333931385a170d3431313131303139333931385a3081ad310b30090603550406130255533111300f06035504080c084e657720596f726b3111300f06035504070c084e657720596f726b31143012060355040b0c0b4644726f6964205265706f31193017060355040a0c10477561726469616e2050726f6a656374311d301b06035504030c14677561726469616e70726f6a6563742e696e666f3128302606092a864886f70d0109011619726f6f7440677561726469616e70726f6a6563742e696e666f30820222300d06092a864886f70d01010105000382020f003082020a0282020100b3cd79121b9b883843be3c4482e320809106b0a23755f1dd3c7f46f7d315d7bb2e943486d61fc7c811b9294dcc6b5baac4340f8db2b0d5e14749e7f35e1fc211fdbc1071b38b4753db201c314811bef885bd8921ad86facd6cc3b8f74d30a0b6e2e6e576f906e9581ef23d9c03e926e06d1f033f28bd1e21cfa6a0e3ff5c9d8246cf108d82b488b9fdd55d7de7ebb6a7f64b19e0d6b2ab1380a6f9d42361770d1956701a7f80e2de568acd0bb4527324b1e0973e89595d91c8cc102d9248525ae092e2c9b69f7414f724195b81427f28b1d3d09a51acfe354387915fd9521e8c890c125fc41a12bf34d2a1b304067ab7251e0e9ef41833ce109e76963b0b256395b16b886bca21b831f1408f836146019e7908829e716e72b81006610a2af08301de5d067c9e114a1e5759db8a6be6a3cc2806bcfe6fafd41b5bc9ddddb3dc33d6f605b1ca7d8a9e0ecdd6390d38906649e68a90a717bea80fa220170eea0c86fc78a7e10dac7b74b8e62045a3ecca54e035281fdc9fe5920a855fde3c0be522e3aef0c087524f13d973dff3768158b01a5800a060c06b451ec98d627dd052eda804d0556f60dbc490d94e6e9dea62ffcafb5beffbd9fc38fb2f0d7050004fe56b4dda0a27bc47554e1e0a7d764e17622e71f83a475db286bc7862deee1327e2028955d978272ea76bf0b88e70a18621aba59ff0c5993ef5f0e5d6b6b98e68b70203010001300d06092a864886f70d0101050500038202010079c79c8ef408a20d243d8bd8249fb9a48350dc19663b5e0fce67a8dbcb7de296c5ae7bbf72e98a2020fb78f2db29b54b0e24b181aa1c1d333cc0303685d6120b03216a913f96b96eb838f9bff125306ae3120af838c9fc07ebb5100125436bd24ec6d994d0bff5d065221871f8410daf536766757239bf594e61c5432c9817281b985263bada8381292e543a49814061ae11c92a316e7dc100327b59e3da90302c5ada68c6a50201bda1fcce800b53f381059665dbabeeb0b50eb22b2d7d2d9b0aa7488ca70e67ac6c518adb8e78454a466501e89d81a45bf1ebc350896f2c3ae4b6679ecfbf9d32960d4f5b493125c7876ef36158562371193f600bc511000a67bdb7c664d018f99d9e589868d103d7e0994f166b2ba18ff7e67d8c4da749e44dfae1d930ae5397083a51675c409049dfb626a96246c0015ca696e94ebb767a20147834bf78b07fece3f0872b057c1c519ff882501995237d8206b0b3832f78753ebd8dcbd1d3d9f5ba733538113af6b407d960ec4353c50eb38ab29888238da843cd404ed8f4952f59e4bbc0035fc77a54846a9d419179c46af1b4a3b7fc98e4d312aaa29b9b7d79e739703dc0fa41c7280d5587709277ffa11c3620f5fba985b82c238ba19b17ebd027af9424be0941719919f620dd3bb3c3f11638363708aa11f858e153cf3a69bce69978b90e4a273836100aa1e617ba455cd00426847f</string>

    <!-- https://guardianproject.info/fdroid/archive -->
    <string name="guardianproject_archive_name" formatted="false" translatable="false">Guardian Project Archive</string>

    <integer name="guardianproject_archive_version">13</integer>
    <integer name="guardianproject_archive_inuse">0</integer>
    <integer name="guardianproject_archive_priority">20</integer>

    <string name="guardianproject_archive_address" formatted="false" translatable="false">https://guardianproject.info/fdroid/archive</string>
    <string name="guardianproject_archive_description" formatted="false" translatable="false">The official repository of The Guardian Project apps for use with F-Droid client. This contains older versions of applications from the main repository.</string>
    <string name="guardianproject_archive_pubkey" formatted="false" translatable="false">308205d8308203c0020900a397b4da7ecda034300d06092a864886f70d01010505003081ad310b30090603550406130255533111300f06035504080c084e657720596f726b3111300f06035504070c084e657720596f726b31143012060355040b0c0b4644726f6964205265706f31193017060355040a0c10477561726469616e2050726f6a656374311d301b06035504030c14677561726469616e70726f6a6563742e696e666f3128302606092a864886f70d0109011619726f6f7440677561726469616e70726f6a6563742e696e666f301e170d3134303632363139333931385a170d3431313131303139333931385a3081ad310b30090603550406130255533111300f06035504080c084e657720596f726b3111300f06035504070c084e657720596f726b31143012060355040b0c0b4644726f6964205265706f31193017060355040a0c10477561726469616e2050726f6a656374311d301b06035504030c14677561726469616e70726f6a6563742e696e666f3128302606092a864886f70d0109011619726f6f7440677561726469616e70726f6a6563742e696e666f30820222300d06092a864886f70d01010105000382020f003082020a0282020100b3cd79121b9b883843be3c4482e320809106b0a23755f1dd3c7f46f7d315d7bb2e943486d61fc7c811b9294dcc6b5baac4340f8db2b0d5e14749e7f35e1fc211fdbc1071b38b4753db201c314811bef885bd8921ad86facd6cc3b8f74d30a0b6e2e6e576f906e9581ef23d9c03e926e06d1f033f28bd1e21cfa6a0e3ff5c9d8246cf108d82b488b9fdd55d7de7ebb6a7f64b19e0d6b2ab1380a6f9d42361770d1956701a7f80e2de568acd0bb4527324b1e0973e89595d91c8cc102d9248525ae092e2c9b69f7414f724195b81427f28b1d3d09a51acfe354387915fd9521e8c890c125fc41a12bf34d2a1b304067ab7251e0e9ef41833ce109e76963b0b256395b16b886bca21b831f1408f836146019e7908829e716e72b81006610a2af08301de5d067c9e114a1e5759db8a6be6a3cc2806bcfe6fafd41b5bc9ddddb3dc33d6f605b1ca7d8a9e0ecdd6390d38906649e68a90a717bea80fa220170eea0c86fc78a7e10dac7b74b8e62045a3ecca54e035281fdc9fe5920a855fde3c0be522e3aef0c087524f13d973dff3768158b01a5800a060c06b451ec98d627dd052eda804d0556f60dbc490d94e6e9dea62ffcafb5beffbd9fc38fb2f0d7050004fe56b4dda0a27bc47554e1e0a7d764e17622e71f83a475db286bc7862deee1327e2028955d978272ea76bf0b88e70a18621aba59ff0c5993ef5f0e5d6b6b98e68b70203010001300d06092a864886f70d0101050500038202010079c79c8ef408a20d243d8bd8249fb9a48350dc19663b5e0fce67a8dbcb7de296c5ae7bbf72e98a2020fb78f2db29b54b0e24b181aa1c1d333cc0303685d6120b03216a913f96b96eb838f9bff125306ae3120af838c9fc07ebb5100125436bd24ec6d994d0bff5d065221871f8410daf536766757239bf594e61c5432c9817281b985263bada8381292e543a49814061ae11c92a316e7dc100327b59e3da90302c5ada68c6a50201bda1fcce800b53f381059665dbabeeb0b50eb22b2d7d2d9b0aa7488ca70e67ac6c518adb8e78454a466501e89d81a45bf1ebc350896f2c3ae4b6679ecfbf9d32960d4f5b493125c7876ef36158562371193f600bc511000a67bdb7c664d018f99d9e589868d103d7e0994f166b2ba18ff7e67d8c4da749e44dfae1d930ae5397083a51675c409049dfb626a96246c0015ca696e94ebb767a20147834bf78b07fece3f0872b057c1c519ff882501995237d8206b0b3832f78753ebd8dcbd1d3d9f5ba733538113af6b407d960ec4353c50eb38ab29888238da843cd404ed8f4952f59e4bbc0035fc77a54846a9d419179c46af1b4a3b7fc98e4d312aaa29b9b7d79e739703dc0fa41c7280d5587709277ffa11c3620f5fba985b82c238ba19b17ebd027af9424be0941719919f620dd3bb3c3f11638363708aa11f858e153cf3a69bce69978b90e4a273836100aa1e617ba455cd00426847f</string>

</resources>

















    /**
     * Verifies the size of the file on disk matches, and then hashes the file to compare with what
     * we received from the signed repo (i.e. {@link Apk#hash} and {@link Apk#hashType}).
     * Bails out if the file sizes don't match to prevent having to do the work of hashing the file.
     */
    public static boolean apkIsCached(File apkFile, Apk apkToCheck) {
        try {
            return apkFile.length() == apkToCheck.size &&
                    verifyApkFile(apkFile, apkToCheck.hash, apkToCheck.hashType);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }










# A signature block file with a .DSA, .RSA, or .EC extension
cert_path_regex = re.compile(r'^META-INF/.*\.(DSA|EC|RSA)$')


def getsig(apkpath):
    """ Get the signing certificate of an apk. To get the same md5 has that
    Android gets, we encode the .RSA certificate in a specific format and pass
    it hex-encoded to the md5 digest algorithm.

    :param apkpath: path to the apk
    :returns: A string containing the md5 of the signature of the apk or None
              if an error occurred.
    """






    # verify the jar signature is correct
    args = [config['jarsigner'], '-verify', apkpath]
    p = FDroidPopen(args)
    if p.returncode != 0:
        logging.critical(apkpath + " has a bad signature!")
        return None

    with zipfile.ZipFile(apkpath, 'r') as apk:
















        # Sign the index...
        signed = os.path.join(repodir, 'index.jar')
        if options.nosign:
            # Remove old signed index if not signing
            if os.path.exists(signed):
                os.remove(signed)
        else:
            args = [config['jarsigner'], '-keystore', config['keystore'],
                    '-storepass:file', config['keystorepassfile'],
                    '-digestalg', 'SHA1', '-sigalg', 'SHA1withRSA',
                    signed, config['repo_keyalias']]
            if config['keystore'] == 'NONE':
                args += config['smartcardoptions']
            else:  # smardcards never use -keypass
                args += ['-keypass:file', config['keypassfile']]
            p = FDroidPopen(args)
            if p.returncode != 0:
                logging.critical("Failed to sign index")
                sys.exit(1)







https://f-droid.org/en/docs/Build_Metadata_Reference






