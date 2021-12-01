#!/bin/sh
## Xe1phix-Tails-Verification.sh

curl --tlsv1 --url https://tails.boum.org/tails-signing.key --output /home/amnesia/Gnupg/tails-signing.key 
curl --tlsv1 --url https://tails.boum.org/tails-signing.key --output /home/amnesia/Gnupg/tails-signing.key  | apt-key add tails-signing.key
curl --tlsv1 --url https://tails.boum.org/tails-signing.key --output /home/amnesia/Gnupg/tails-signing.key  | gpg --keyid-format long --import tails-signing.key


curl https://tails.boum.org/tails-signing.key | gpg --import
wget -q -O - https://tails.boum.org/tails-signing.key | gpg --import


gpg --keyid-format long --import tails-signing.key

 gpg --no-options --keyid-format 0xlong --verify tails-amd64-3.7.iso.sig tails-amd64-3.7.iso 
 
 gpg: Signature made 2018-05-08T01:18:06 UTC
gpg:                using RSA key 2FAF9BA0D65BB371F0BC2D463020A7A9C2B72733
gpg: Good signature from "Tails developers <tails@boum.org>" [undefined]
gpg:                 aka "Tails developers (offline long-term identity key) <tails@boum.org>" [full]


curl --verbose --progress-bar --tlsv1 --url https://tails.boum.org/<tails.iso> \
       | tee >(sha1sum > dvd.sha1) > dvd.iso
       
gpg --verify Erinn Clark.asc sha256sums.txt



Tails developers <tails@boum.org>" [full]
gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0xA490D0F4D311A4153E2BB7CADBB802B258ACD84F
gpg --export A490D0F4D311A4153E2BB7CADBB802B258ACD84F | sudo apt-key add -


wget https://tails.boum.org/tails-signing.key
gpg --import < tails-signing.key


gpg --lsign-key A490D0F4D311A4153E2BB7CADBB802B258ACD84F
gpg --sign-key A490D0F4D311A4153E2BB7CADBB802B258ACD84F
gpg --send-keys A490D0F4D311A4153E2BB7CADBB802B258ACD84F

wget --continue http://dl.amnesia.boum.org/tails/stable/tails-i386-2.4/tails-i386-2.4.iso
wget https://tails.boum.org/torrents/files/tails-i386-2.4.iso.sig


	Erinn Clark {'Depreciated'}  Signing Key : (0x63FEE659) Signed Earlier Tor Browser Bundles 		erinn@torproject.org
gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x8738A680B84B3031A630F2DB416F061063FEE659
gpg --export 8738A680B84B3031A630F2DB416F061063FEE659 | sudo apt-key add -
        Key fingerprint = 8738 A680 B84B 3031 A630  F2DB 416F 0610 63FE E659

	Erinn Clark 'Stable' Signing Key: (0xF1F5C9B5) 								erinn@torproject.org
gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0xC2E34CFC13C62BD92C7579B56B8AAEB1F1F5C9B5
gpg --export C2E34CFC13C62BD92C7579B56B8AAEB1F1F5C9B5 | sudo apt-key add -
         Key fingerprint = C2E3 4CFC 13C6 2BD9 2C75  79B5 6B8A AEB1 F1F5 C9B5

Tor Project Archive (0x886DDD89)  {'Depreciated'}
gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0xA3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -
          Key fingerprint = A3C4 F0F9 79CA A22C DBA8  F512 EE8C BC9E 886D DD89

Mike Perry 'Stable' Regular Use Signing Key: (0x0E3A92E4)  						mikeperry@torproject.org
gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0xC963C21D63564E2B10BB335B29846B3C683686CC
gpg --export C963C21D63564E2B10BB335B29846B3C683686CC | sudo apt-key add - 
          Key fingerprint = C963 C21D 6356 4E2B 10BB  335B 2984 6B3C 6836 86CC

T(A)ILS Developers Signing key  (0xBE2CD9C1) 			Amnesia@boum.org
gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x0D24B36AA9A2A651787876451202821CBE2CD9C1
gpg --export 0D24B36AA9A2A651787876451202821CBE2CD9C1 | sudo apt-key add -
         Key fingerprint = 0D24 B36A A9A2 A651 7878  7645 1202 821C BE2C D9C1
curl --tlsv1 --url https://tails.boum.org/tails-signing.key --output /home/amnesia/Gnupg/tails-signing.key  && gpg --keyid-format long --import tails-signing.key



Jacob Appelbaum Signing Key: (0xD255D3F5C868227F) && (0x875690BC9192B06291B2) && (0x756AFA7F0E44D487F03F)	jacob@torproject.org
gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0xD2C67D20E9C36C2AC5FE74A2D255D3F5C868227F
gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x043E0E69DD56BA595905875690BC9192B06291B2
gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0xD6A948CF297F753930B4756AFA7F0E44D487F03F
gpg --export D2C67D20E9C36C2AC5FE74A2D255D3F5C868227F | sudo apt-key add -
gpg --export 043E0E69DD56BA595905875690BC9192B06291B2 | sudo apt-key add -
gpg --export D6A948CF297F753930B4756AFA7F0E44D487F03F | sudo apt-key add -
           Key fingerprint = D2C6 7D20 E9C3 6C2A C5FE  74A2 D255 D3F5 C868 227F
           Key fingerprint = 043E 0E69 DD56 BA59 5905  8756 90BC 9192 B062 91B2
           Key fingerprint = D6A9 48CF 297F 7539 30B4  756A FA7F 0E44 D487 F03F



