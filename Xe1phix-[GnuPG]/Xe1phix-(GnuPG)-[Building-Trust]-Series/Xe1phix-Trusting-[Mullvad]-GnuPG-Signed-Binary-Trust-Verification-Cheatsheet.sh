#!/bin/sh
##-==================================================-##
##    [+] Xe1phix-[GnuPG]-Trusting-[MullvadVPN].sh
##-==================================================-##


echo "##-==============================================-##"
echo "     [+] Generate Strong GnuPG Key (4096 Bits):     "
echo "##-==============================================-##"
gpg --enable-large-rsa --full-gen-key



echo "##-=========================================-##"
echo "     [+] Fetch Mullvads GPG Signing Key:       "
echo "##-=========================================-##"
gpg --keyserver pool.sks-keyservers.net --recv-keys A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF


echo "##-=================================================-##"
echo "     [+] Curl Fetch Mullvads .asc (Require SSL):       "
echo "##-=================================================-##"
curl --verbose --ssl-reqd --url https://www.mullvad.net/static/mullvad-support-mail.asc --output ~/mullvad-support-mail.asc
curl --verbose --ssl-reqd --url https://www.mullvad.net/static/mullvad-code-signing.asc --output ~/mullvad-code-signing.asc


##-==================================================-##
##   [+] Specifying A Specific Version of SSL/TLS:
##-==================================================-##
## curl --verbose --tlsv1.2 --url https://www.mullvad.net/static/mullvad-code-signing.asc --output ~/mullvad-code-signing.asc 
## curl --verbose --tlsv1.3 --url https://www.mullvad.net/static/mullvad-code-signing.asc --output ~/mullvad-code-signing.asc 
## curl --verbose --sslv3 --url https://www.mullvad.net/static/mullvad-code-signing.asc --output ~/mullvad-code-signing.asc 



echo "##-==========================================-##"
echo "     [+] Import Mullvads GPG Signing Key:       "
echo "##-==========================================-##"
gpg --keyid-format 0xlong --import mullvad-support-mail.asc
gpg --keyid-format 0xlong --import mullvad-code-signing.asc



echo "##-===========================================-##"
echo "     [+] Print Mullvads GPG Fingerprints:        "
echo "##-===========================================-##"
gpg --keyid-format 0xlong --fingerprint 0xA1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF


echo "##-==============================================-##"
echo "     [+] Mullvads GPG Fingerprints (Verified):      "
echo "##-==============================================-##"
echo "Primary key fingerprint: A119 8702 FC3E 0A09 A9AE  5B75 D5A1 D4F2 66DE 8DDF"



echo "##-================================-##"
echo "     [+] Sign Mullvads GPG Key:       "
echo "##-================================-##"
gpg --lsign A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF				## gpg --edit-key A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF


echo "##-===================================================================-##"
echo "     [+] Verify Mullvads .deb against Their Published Signed .asc:"
echo "##-===================================================================-##"
gpg --keyid-format 0xlong -v --verify mullvad_65-1_all.deb.asc mullvad_65-1_all.deb





echo "##-====================================================-##"
echo "     [?] The Resulting Output Should Be As Follows:       "
echo "##-====================================================-##"


echo "##-======================================================================================-##"
echo "## -------------------------------------------------------------------------------------- ##"
echo "		gpg: armor header: Version: GnuPG v2"
echo "		gpg: Signature made Mon 04 Sep 2017 01:58:42 PM UTC"
echo "		gpg:                using RSA key 0xA26581F219C8314C"
echo "		gpg: using subkey 0xA26581F219C8314C instead of primary key 0xD5A1D4F266DE8DDF"
echo "		gpg: using pgp trust model"
echo "		gpg: Good signature from "Mullvad (code signing) <admin@mullvad.net>" [full]"
echo "		gpg: binary signature, digest algorithm SHA256, key algorithm rsa4096"
echo "## -------------------------------------------------------------------------------------- ##"
echo "##-======================================================================================-##"








echo "##-================================================-##"
echo "   [?] Plaintext Version of Mullvads GnuPG Key:"
echo "##-================================================-##"



echo "-----BEGIN PGP PUBLIC KEY BLOCK-----"
echo "Version: GnuPG v2"
echo ""
echo "mQINBFgRmCoBEAChee2rs/braqjqim1D+uvTBpPZzkpccJVb2SqhErQKs54iJVyo"
echo "H5pNrGR4VIzFRUnY7fbATo2Ej+0MlglXahl4ok93XmeDz04P5rH2NKnLvWYdaK1C"
echo "9Lvpq22t1nytJuhc124UBahVVEYjc7l2+JGdTh7WvLj8FXqfnnmI1upVU48S70RL"
echo "oM3tSDZqQaO3OGCc0znMNBGI/uKNNwc6Omm6KPvczOhci7bnKt0b0R6TrXufvgOG"
echo "y1DM9sntIbXtpIjOuZdTWyrGTm/AvT6zddPFjN8SN6ZIfoRmJT6ROB6ZTtiz/d20"
echo "VJ87QPEfVRKrMImZxtkJtSliojZB/I3/bkP7A4pvgJ6cJ+ErwW4cfqc3DrWaZY+D"
echo "4AZnk71FA6C5rQdkFbfkgyUMY1WeKX+8N/R+e5oLGmoVI/fdHu1z0JkJJvEraAO9"
echo "+qX2mOcW5h/NRxv0Xw57fjMhnMha7bWs8Jn5AchDPJZs1U64Wr36FuSvcdxc0ON/"
echo "WaX4RL/J5OtJHu+2FB+UB1/JuICdOP07/KFxUJod43KwwBctLUHOOz3m1KIVcnXR"
echo "l6+gNQ7vxGm+xghN/zG7lgPLuw5ToCCkMLkQydsRPRSlm0f2zqbQUD3jn+4zZ2ma"
echo "HBHcu6Ld8SSGPp5XIauAKhqZA9IkD5VPgqlrm0iJ4emzPYGp7PMFFdH3qQARAQAB"
echo "tCpNdWxsdmFkIChjb2RlIHNpZ25pbmcpIDxhZG1pbkBtdWxsdmFkLm5ldD6JAjUE"
echo "EwEIAB8CGwMCHgECF4AFAlgR6R8ECwkIBwUVCgkICwQWAgMBAAoJENWh1PJm3o3f"
echo "muQQAJElHN6lLhpOgrbRprJAR15HfRI0Leoomfu5V53Qieqf+6O3TF4PC9JRn+v8"
echo "NYOMsBmBgosvO8YcABA3wYTW6qyRGr+8zQePltEe/J9SE3oCbb4K5KWEThiicZ6R"
echo "o0sJgXB3l0CIHVP+/3bWeZlBpTJNMLOEM+WsEsTe6v7hZfF7HIubVdKSIbQy7T3X"
echo "nsk8840rt5LjJiNtSpsG+EJOIGEdXH5FAis35pTLrbkgnL3Evyjd2OW1grciqF+v"
echo "7aba2g/2zpEGEdtbJKO5C4nG9CHcN5BlaSev0oQlKWuRSG3igwauZFe/0RQPkH/V"
echo "kCOHA3l8NTlublQCdLLLrJJyX7aODH+AKLaVci17ogtGwwO+xNh0h4ejM0QuMLYV"
echo "giMCpxRT5uUuOHbh3by1rwTSb+8dvIw3KyW1TbZ6LFCQHX+8Zs7xU7KQ6tGZ6Pvr"
echo "Fhk/YiM8J+Fe+rBGwEcUfo/ALv4p7qHpRVA7CvdrzKg66iaN+iPQzsptamoSLsCj"
echo "SYbjIby74X0vppRAg7sDXiAxJSRPXM3h1xO83yk1HMrswwWAUuJeToYRXOHYl5zN"
echo "i3E0D6I5Zk1ioO9XPE7oILwJ7YaO4XuC3UuNMwWPSvOoJxbnsUdHpenITvbpe9DP"
echo "z4HGzZWbUtShFDq77MDhv9vkNaFUOgP7AfO5N/35pVCkI4m1uQINBFgRmCoBEADT"
echo "5YK+TLcGSzC4ML7t8VW+rVpYyY3pswX8dL058LYfCIrlaNa14/UvINvjA5529SWr"
echo "jmmDluD8fqtMSFHw6l+XwPMOwvETAjaMLS6c/MLFmw2gHR2ARHBmLEn/ux9kZ03Y"
echo "dEKak5wvkUVqLV7EgGnvfrI0FUw/gaIfdtAt0dcvpAG0bILXQtcYEj7BtiAdxiWL"
echo "O8HMUzD7kj0Q2IUbA3bO4dAtJtXDyY+Ash/kqLzm+0kZtzk4FLWZT2CMw9l73mIT"
echo "/f03+y8oBe1KhZ5FzqgUxQXdjV5hkWyFNbBn4+dsyoMltnVDPkRznIHDWJXiKUV+"
echo "buSQ+xewO/flwrwcgbdTtH5qfuxtNBA2AkVs/dul8FJHeSCB7at6Vy1m8/xFlxgc"
echo "QOk/wwiDKLBub0uIE6TfNs7SvAOUuZP5syLQq8ZeyYMWGrWQKgAEmHlXr0uCrqVF"
echo "O5vjaja8Zwc6wdApiFxjiBzl3z7UiE3fafpeO9nqLwaZqz0RPCEpvCrkpDi4Gl2W"
echo "nfWmQbj2jEpUER1osJhvNRCEfA12IUWjp1vFJhy31i6gTXdCxVBasQrxpJBEZnuJ"
echo "57yIZ+FbdMI0wQD2OMdUYxx4o9p6aGwhotSBrgpM0cfZ5LruP6MjBfWKqLnZBuYk"
echo "prqWeh5rgtXIebsiGYp7V3Ay9pcoilbzh53/wU6y+wARAQABiQIfBBgBCAAJBQJY"
echo "EZgqAhsMAAoJENWh1PJm3o3fbfoP/RfOil8d3hNK+qgG4Xh46bF/UmGzorYbVzzP"
echo "myXXRHTMh3/Br2tPOOnhP65nKJnv8pqCuK1UOJpfXUXDyRpAP7opiWRaS0gbU9s6"
echo "RBy499P/LyMmvZbM4YkpxwPJkC6JaITQ+ZtnPQp+MYLizsz5OD8utyfoPWDOdaEf"
echo "3JHOvupcItDL3DDKw5zPzrI6pKc0IMObO5VI/uU3BIf0x+FKh2rhMVMI+Psapotm"
echo "qhpaPZoz/QPapS2WiMNr7cInLxx7/fv/RLEr5WSVn1eAKkKuXUO/VB5+h4GdP/YV"
echo "boBW4wMneEEkJX3iLr/IM1GQdQK/db4fyWAKh7LhzS9ZCVMxm5BU6GkId7GI2jFE"
echo "djmedt6iF6Tyk0/49WjU/qAZ9H0IHgpyNCwUqPpzWgRiiIbZryRXycht/rH6zuL1"
echo "8p5N6r7AgT6s6kCHfrNK/zxMOzylUuwng1EnLCmlg88PoCCQpaNFZkqwIR0LCh3p"
echo "Xp8zAp+0Sx2td1FtjbEw+OaNCmmJoMqoejuw0nSOFdQUUNAB5WGeZQLoPaastanW"
echo "ir6XcUChoy/1osuovAPNKpWWUxWDdW+62mV8s2ArkLzhgl0FmLZhu+VBKrQaNUKV"
echo "WmPnMRZF6f1C3M8l5DtT1VzfEr1A9ON6uZzKITLlJdBltVFkV7qJTsxbsoj0AJj7"
echo "0VY4XEjauQINBFgR4mgBEACsFJ+BkT+yBxB0E2MNUAcW5stDgscDOJOAXS/ViYd8"
echo "68FqC87VnG+bgTqG2atRqb493RoCHwZyL3L9JniadSk35d9JEQBWzCPff+kEy5Uc"
echo "bwzvSUJyCfjFdxU4YgH/bMt+RXi1mVjLcGTthRp4IfBxQcluI//rxP1kurrqq+lO"
echo "wj7n+h1wxrdhvXXDiAeBJqlQcBjeT0VLc74PYQJ3SbpeX1aFaxsVATGpgXf3SWp+"
echo "8vRCmzM9CnyZW8BeaXBrkwiZQEOeiqnQ0MWaD/8Fs6WWfiyoObJcadmS7HgqCfw7"
echo "SwjSUjSPAr+Vr02P83S59u8ql0RWtDI8CCXcSc1t4u52lvXBdO3nKa9+PeW64I+A"
echo "UfqgJOmfhWZsoImV1pCx+RzY6luFp7H7JVACAi3Z1s24fsRhN5wVZ/hjKn7xGPv0"
echo "O+zFVGWXs/JKl6Bv7xMR0epL+D0d13ahPZYHyLqLfdeJwg2HT1BUAPy+QCy5rhzS"
echo "iEjeygqVzwNTcBPnu1PFhzXSdGMvHKTFXwO5xPwqanvKUd9zH6Xxan5wAJL7yRPq"
echo "7/MSEqUFiE+OfVTeZ3PDduLrkrQm0ZIgTl4EkUNn70YbzrPnEDh7EMETNnAqjNU3"
echo "5iwELxRyxjUdSaIuF/5gSfc4DG/c8miUrYAaXyqMuJWuF7aNnVnSQJDZCjnf//Yy"
echo "KQARAQABiQQ+BBgBCAAJBQJYEeJoAhsCAikJENWh1PJm3o3fwV0gBBkBCAAGBQJY"
echo "EeJoAAoJEKJlgfIZyDFMyBwP/ih4/pKyfQOdgP03IXK0v9dhKOs+PcSAd4BC+ACV"
echo "kDz+N4Pui7/6FJ7+hSJE7Tf2vcWYYbtTrVCz335VCf5zWC/Tz8aXs9MOBlMeZNOS"
echo "2Fsi8P1KOv2BD7qi+m6fkHJ59hDXp2SzvmYRNRgn3N1QpuJl6bjssLmG7X+8NrNA"
echo "JZedzfXmvxDfnxaqKTwGotlJXVo5b/wB1ZXn7yr3zecuXKvcG1SJTGCSyK98jyip"
echo "S/0qAOqzd6FPbNEl/4ehKPX5STdZytTzN8lcbtfTMUA6qLqe/5Tvt50n8yDD3bEh"
echo "ripRSaC2BoVDADwxo7kDhTO6c1xCNMdG/9dHMelbzOPuxJhVMkNzL+dR5V6Q3Clt"
echo "I2rjANqWq/3G7kA4oaItoYOYnh9J8a7P/bkMFbrGEYmaYu9PCqLY5NzqaCKlNyJP"
echo "Fy8u0TdBhiyoBWWarTN6fZwTG6MotHPi9q0iWPfsb9kyoRJWIcvEJq+Vi0wE0+9/"
echo "kXgibqh76U5JekysGV/dBgXaPF4XAPCpBaEe9sbD2PVeUDZPuVeo3c8iGPK1NxmJ"
echo "dt1ktfCcuV3MYCo1DGifuOCCvVaJms6IEFjLPAEQmTGhRSVzTWZ7J8HoDqulhlJh"
echo "HxLT7KI9z85238zplUarSEZ42gNT5SQd35prGVlJDVBwRm2NmJurcfU/EcPi++eD"
echo "0hJhWrYP/3lW/OOkR5NZCK8HhKYM2kBcAsOC/6x5vV1VISslZY2LB3jKq+XhXlPO"
echo "cEmQVMPliBx4yuFrPOKk1+87D9bEL5LJBQskgQwFe2Pg9QirIYflO+P+1LJK3U/g"
echo "3NnlkSrOTRV0M/AvhtU/8R3V2V423pm3sjQsaRdMMtWGfsFNJxvotBkwgEDwDu7h"
echo "sZqzL0zFucm+iMAhGnqi+EZEPXwbX1Utp7S8edBCztfytQMjnJ6jv4UCz///rc3i"
echo "8IDlMo2d19CW/psPS4v7lns5g9oqCGpRbGRllrBV1M/o7bs7+1NyvPTJm9UAmt5U"
echo "iApao4vt4YOG5w0vYd0t50pDS/j3TGjbakgxZpNUMpAgrhnelClKDsXbCVGCyhlJ"
echo "ZOw9Q9t4vIAhFFSpxEDl1NREOUInoK3R4yo4Ep4sq6cbfZvoyAYZf1zpQHQX9OBN"
echo "DKp1jwGLA3+0Jna2/1QUYFLjFiz9bdL+1nT9k/RStFBauRh529r+M1WlkwqNIL+L"
echo "bRGm0rXbWu9eiLhq2ldnfIADOtccUll10RznrjumqgYYw2CI0YUudzpzIghAKZyo"
echo "THYPADmBfvN2pZa/KU3c1OSKHOH2b91Xi97k3u0fECMHLgXctA3BkQ69fONSzx/c"
echo "abgtcydAU0wAD3mG3mr1XI96uOMeVNK0wgYyO5VhzZNziSFhls0D"
echo "=kwTD"
echo "-----END PGP PUBLIC KEY BLOCK-----"
