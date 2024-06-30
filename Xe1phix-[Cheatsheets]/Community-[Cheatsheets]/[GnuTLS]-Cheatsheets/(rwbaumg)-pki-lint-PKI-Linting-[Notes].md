# PKI Linting Notes

## OpenSSL
OpenSSL provides the ```openssl verify``` command for validating X.509 certificates.

To verify a certificate against security Level 2 requirements, you could run:
```bash
openssl verify -x509_strict -auth_level 2 /path/to/cert.crt 2>&1
```

To perform a more complete verification, you could run something like:
```bash
openssl verify -verbose \
  -show_chain \
  -x509_strict \
  -auth_level 2 \
  -verify_name default \
  -purpose sslserver \
  -verify_hostname test.example.com \
  -policy_print \
  -policy_check \
  -policy 2.23.140.1.2.2 \
  -CAfile /path/to/ca/chain.pem \
  /path/to/cert.crt
```

Note that the ```auth_level``` argument is only available with newer versions of ```openssl```.

It is also possible to check revocation information for a certificate (including, optionally, all certificates in the chain), for example, using ```openssl verify```. To do so, use the ```-crl_check``` argument to validate the CRL for the specified certificate, or ```-crl_check_all``` to do the same for every certificate in the trust chain. CRL checking arguments can be passed to ```openssl verify``` in combination with other verification, e.g. by adding the desired argument to the above example.

The following security levels are defined by OpenSSL for certificate verification (taken from ```man SSL_CTX_set_security_level```).

**Certificates must be equivalent to *Level 2* or greater security in order to meet baseline requirements for certificate issuance.**

| Level   | Details                                                                                                                                                                                                                                                                                                                                                                                                                          |
| :-----  | :----                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Level 0 | Everything is permitted. This retains compatibility with previous versions of OpenSSL.                                                                                                                                                                                                                                                                                                                                           |
| Level 1 | The security level corresponds to a minimum of 80 bits of security. Any parameters offering below 80 bits of security are excluded. As a result RSA, DSA and DH keys shorter than 1024 bits and ECC keys shorter than 160 bits are prohibited. All export ciphersuites are prohibited since they all offer less than 80 bits of security. SSL version 2 is prohibited. Any ciphersuite using MD5 for the MAC is also prohibited. |
| Level 2 | Security level set to 112 bits of security. As a result RSA, DSA and DH keys shorter than 2048 bits and ECC keys shorter than 224 bits are prohibited.  In addition to the level 1 exclusions any ciphersuite using RC4 is also prohibited. SSL version 3 is also not allowed. Compression is disabled.                                                                                                                          |
| Level 3 | Security level set to 128 bits of security. As a result RSA, DSA and DH keys shorter than 3072 bits and ECC keys shorter than 256 bits are prohibited.  In addition to the level 2 exclusions ciphersuites not offering forward secrecy are prohibited. TLS versions below 1.1 are not permitted. Session tickets are disabled.                                                                                                  |
| Level 4 | Security level set to 192 bits of security. As a result RSA, DSA and DH keys shorter than 7680 bits and ECC keys shorter than 384 bits are prohibited.  Ciphersuites using SHA1 for the MAC are prohibited. TLS versions below 1.2 are not permitted.                                                                                                                                                                            |
| Level 5 | Security level set to 256 bits of security. As a result RSA, DSA and DH keys shorter than 15360 bits and ECC keys shorter than 512 bits are prohibited.                                                                                                                                                                                                                                                                          |

The following ```-purpose``` strings are supported by ```openssl verify```:
-   ```sslclient```
-   ```sslserver```
-   ```nssslserver```
-   ```smimesign```
-   ```smimeencrypt```

The ```-verify_name``` option is used to set default verification policies, and is inferred from ```-purpose``` when not specified (making them functionally equivalent). The following names are supported:
-   ```default```
-   ```pkcs7```
-   ```smime_sign```
-   ```ssl_client```
-   ```ssl_server```

## Key Purposes
Common Extended Key Usage (EKU) OIDs are listed below:

| Purpose            | Object Identifier (OID)        |
| :---               |    :----:                      |
| anyEKU             | ```2.5.29.37.0```              |
| serverAuth         | ```1.3.6.1.5.5.7.3.1```        |
| clientAuth         | ```1.3.6.1.5.5.7.3.2```        |
| codeSigning        | ```1.3.6.1.5.5.7.3.3```        |
| emailProtection    | ```1.3.6.1.5.5.7.3.4```        |
| timeStamping       | ```1.3.6.1.5.5.7.3.8```        |
| OCSPSigning        | ```1.3.6.1.5.5.7.3.9```        |
| msKernelCode       | ```1.3.6.1.4.1.311.61.1.1```   |
| msCodeInd          | ```1.3.6.1.4.1.311.2.1.21```   |
| msCodeCom          | ```1.3.6.1.4.1.311.2.1.22```   |
| id-kp-dvcs         | ```1.3.6.1.5.5.7.3.10```       |
| secureShellClient  | ```1.3.6.1.5.5.7.3.21```       |
| secureShellServer  | ```1.3.6.1.5.5.7.3.22```       |
| msDocSigning       | ```1.3.6.1.4.1.311.10.3.12```  |
| msSmartcardLogin   | ```1.3.6.1.4.1.311.20.2.2```   |
| msTimestamp        | ```1.3.6.1.4.1.311.10.3.2```   |
| BitLocker          | ```1.3.6.1.4.1.311.67.1.1```   |
| msEFS              | ```1.3.6.1.4.1.311.10.3.4```   |
| msEFSRecovery      | ```1.3.6.1.4.1.311.10.3.4.1``` |
| msDigitalRights    | ```1.3.6.1.4.1.311.10.5.1```   |
| msCTLSign          | ```1.3.6.1.4.1.311.10.3.1```   |
| scvpServer         | ```1.3.6.1.5.5.7.3.15```       |
| scvpClient         | ```1.3.6.1.5.5.7.3.16```       |
| EAPOVRPPP          | ```1.3.6.1.5.5.7.3.13```       |
| EAPOVRLAN          | ```1.3.6.1.5.5.7.3.14```       |
| adobePDFSigning    | ```1.2.840.113583.1.1.5```     |
| intelAMT           | ```2.16.840.1.113741.1.2.3```  |
| etsi-tslSigning    | ```0.4.0.2231.3.0```           |

### Microsoft Windows
The table below shows Extended Key Usage Object Identifiers (OIDs) supported by Microsoft Windows, as defined by the [IX509ExtensionEnhancedKeyUsage](https://docs.microsoft.com/en-us/windows/desktop/api/CertEnroll/nn-certenroll-ix509extensionenhancedkeyusage) interface:

| Name                                       | Object Identifier (OID)        | Description                                                                                                                                                                                                                                                                                        |
| :--                                        | :--:                           | :--                                                                                                                                                                                                                                                                                                |
| ```XCN_OID_ANY_APPLICATION_POLICY```       | ```1.3.6.1.4.1.311.10.12.1```  | The applications that can use the certificate are not restricted.                                                                                                                                                                                                                                  |
| ```XCN_OID_AUTO_ENROLL_CTL_USAGE```        | ```1.3.6.1.4.1.311.20.1```     | The certificate can be used to sign a request for automatic enrollment in a certificate trust list (CTL).                                                                                                                                                                                          |
| ```XCN_OID_DRM```                          | ```1.3.6.1.4.1.311.10.5.1```   | The certificate can be used for digital rights management applications.                                                                                                                                                                                                                            |
| ```XCN_OID_DS_EMAIL_REPLICATION```         | ```1.3.6.1.4.1.311.21.19```    | The certificate can be used for Directory Service email replication.                                                                                                                                                                                                                               |
| ```XCN_OID_EFS_RECOVERY```                 | ```1.3.6.1.4.1.311.10.3.4.1``` | The certificate can be used for recovery of documents protected by using Encrypting File System (EFS).                                                                                                                                                                                             |
| ```XCN_OID_EMBEDDED_NT_CRYPTO```           | ```1.3.6.1.4.1.311.10.3.8```   | The certificate can be used for Windows NT Embedded cryptography.                                                                                                                                                                                                                                  |
| ```XCN_OID_ENROLLMENT_AGENT```             | ```1.3.6.1.4.1.311.20.2.1```   | The certificate can be used by an enrollment agent.                                                                                                                                                                                                                                                |
| ```XCN_OID_IPSEC_KP_IKE_INTERMEDIATE```    | ```1.3.6.1.5.5.8.2.2```        | The certificate can be used for Internet Key Exchange (IKE).                                                                                                                                                                                                                                       |
| ```XCN_OID_KP_CA_EXCHANGE```               | ```1.3.6.1.4.1.311.21.5```     | The certificate can be used for archiving a private key on a certification authority.                                                                                                                                                                                                              |
| ```XCN_OID_KP_CTL_USAGE_SIGNING```         | ```1.3.6.1.4.1.311.10.3.1```   | The certificate can be used to sign a CTL.                                                                                                                                                                                                                                                         |
| ```XCN_OID_KP_DOCUMENT_SIGNING```          | ```1.3.6.1.4.1.311.10.3.12```  | The certificate can be used for signing documents.                                                                                                                                                                                                                                                 |
| ```XCN_OID_KP_EFS```                       | ```1.3.6.1.4.1.311.10.3.4```   | The certificate can be used to encrypt files by using the Encrypting File System.                                                                                                                                                                                                                  |
| ```XCN_OID_KP_KEY_RECOVERY```              | ```1.3.6.1.4.1.311.10.3.11```  | The certificate can be used to encrypt and recover escrowed keys.                                                                                                                                                                                                                                  |
| ```XCN_OID_KP_KEY_RECOVERY_AGENT```        | ```1.3.6.1.4.1.311.21.6```     | The certificate is used to identify a key recovery agent.                                                                                                                                                                                                                                          |
| ```XCN_OID_KP_LIFETIME_SIGNING```          | ```1.3.6.1.4.1.311.10.3.13```  | Limits the validity period of a signature to the validity period of the certificate. This restriction is typically used with the XCN_OID_PKIX_KP_CODE_SIGNING OID value to indicate that new time stamp semantics should be used.                                                                  |
| ```XCN_OID_KP_QUALIFIED_SUBORDINATION```   | ```1.3.6.1.4.1.311.10.3.10```  | The certificate can be used to sign cross certificate and subordinate certification authority certificate requests. Qualified subordination is implemented by applying basic constraints, certificate policies, and application policies. Cross certification typically requires policy mapping.   |
| ```XCN_OID_KP_SMARTCARD_LOGON```           | ```1.3.6.1.4.1.311.20.2.2```   | The certificate enables an individual to log on to a computer by using a smart card.                                                                                                                                                                                                               |
| ```XCN_OID_KP_TIME_STAMP_SIGNING```        | ```1.3.6.1.4.1.311.10.3.2```   | The certificate can be used to sign a time stamp to be added to a document. Time stamp signing is typically part of a time stamping service.                                                                                                                                                       |
| ```XCN_OID_LICENSE_SERVER```               | ```1.3.6.1.4.1.311.10.6.2```   | The certificate can be used by a license server when transacting with Microsoft to receive licenses for Terminal Services clients.                                                                                                                                                                 |
| ```XCN_OID_LICENSES```                     | ```1.3.6.1.4.1.311.10.6.1```   | The certificate can be used for key pack licenses.                                                                                                                                                                                                                                                 |
| ```XCN_OID_NT5_CRYPTO```                   | ```1.3.6.1.4.1.311.10.3.7```   | The certificate can be used for Windows Server 2003, Windows XP, and Windows 2000 cryptography.                                                                                                                                                                                                    |
| ```XCN_OID_OEM_WHQL_CRYPTO```              | ```1.3.6.1.4.1.311.10.3.7```   | The certificate can be used for used for Original Equipment Manufacturers (OEM) Windows Hardware Quality Labs (WHQL) cryptography.                                                                                                                                                                 |
| ```XCN_OID_PKIX_KP_CLIENT_AUTH```          | ```1.3.6.1.5.5.7.3.2```        | The certificate can be used for authenticating a client.                                                                                                                                                                                                                                           |
| ```XCN_OID_PKIX_KP_CODE_SIGNING```         | ```1.3.6.1.5.5.7.3.3```        | The certificate can be used for signing code.                                                                                                                                                                                                                                                      |
| ```XCN_OID_PKIX_KP_EMAIL_PROTECTION```     | ```1.3.6.1.5.5.7.3.4```        | The certificate can be used to encrypt email messages.                                                                                                                                                                                                                                             |
| ```XCN_OID_PKIX_KP_IPSEC_END_SYSTEM```     | ```1.3.6.1.5.5.7.3.5```        | The certificate can be used for signing end-to-end Internet Protocol Security (IPSEC) communication.                                                                                                                                                                                               |
| ```XCN_OID_PKIX_KP_IPSEC_TUNNEL```         | ```1.3.6.1.5.5.7.3.6```        | The certificate can be used for singing IPSEC communication in tunnel mode.                                                                                                                                                                                                                        |
| ```XCN_OID_PKIX_KP_IPSEC_USER```           | ```1.3.6.1.5.5.7.3.7```        | The certificate can be used for an IPSEC user.                                                                                                                                                                                                                                                     |
| ```XCN_OID_PKIX_KP_OCSP_SIGNING```         | ```1.3.6.1.5.5.7.3.9```        | The certificate can be used for Online Certificate Status Protocol (OCSP) signing.                                                                                                                                                                                                                 |
| ```XCN_OID_PKIX_KP_SERVER_AUTH```          | ```1.3.6.1.5.5.7.3.1```        | The certificate can be used for OCSP authentication.                                                                                                                                                                                                                                               |
| ```XCN_OID_PKIX_KP_TIMESTAMP_SIGNING```    | ```1.3.6.1.5.5.7.3.8```        | The certificate can be used for signing public key infrastructure timestamps.                                                                                                                                                                                                                      |
| ```XCN_OID_ROOT_LIST_SIGNER```             | ```1.3.6.1.4.1.311.10.3.9```   | The certificate can be used to sign a certificate root list.                                                                                                                                                                                                                                       |
| ```XCN_OID_WHQL_CRYPTO```                  | ```1.3.6.1.4.1.311.10.3.5```   | The certificate can be used for Windows Hardware Quality Labs (WHQL) cryptography.                                                                                                                                                                                                                 |

## Mozilla NSS
The Mozilla Network Security Service (NSS) provides the following tools for certificate validation:
-   ```vfychain```: Verifies certificate chains.
-   ```certutil```: Manages keys and certificate in both NSS databases and other NSS tokens.

To validate a certificate chain using ```vfychain```, pass each CA certificate in the chain using ```-t /path/to/ca.crt```, and pass the PEM-encoded certificate to be validated using ```-a /path/to/cert.crt```. For example:
```bash
vfychain -v -pp -u 4 -a /path/to/emailsign.crt -t ca/root-ca.crt -t ca/int-ca.crt
```

To validate revocation information for a chain or leaf certificate using ```vfychain```, you can use the ```-g``` and ```-m``` arguments. For example:
```bash
vfychain -vv -pp -u 4 -T \
  -g leaf -h requireFreshInfo \
  -m crl -s requireInfo \
  -a /path/to/emailsign.crt \
  -t ca/root-ca.crt -t ca/int-ca.crt
```

The following arguments can be passes to ```vfychain``` to control validation:

| Argument              | Description                                                                                                                                                                                                                              |
| :---                  |    :----                                                                                                                                                                                                                                 |
| ```-v```              | Verbose mode. Prints root cert subject(double the argument for whole root cert info).                                                                                                                                                    |
| ```-p```              | Use PKIX Library to validate certificate by calling ```CERT_VerifyCertificate```.                                                                                                                                                        |
| ```-pp```             | Use PKIX Library to validate certificate by calling ```CERT_PKIXVerifyCert```.                                                                                                                                                           |
| ```-f```              | Enable cert fetching from AIA URL.                                                                                                                                                                                                       |
| ```-a```              | The following certfile is base64 encoded.                                                                                                                                                                                                |
| ```-t```              | Following cert is explicitly trusted (overrides db trust).                                                                                                                                                                               |
| ```-T```              | Trust both explicit trust anchors (```-t```) and the database. (Without this option, the default is to only trust certificates marked ```-t```, if there are any, or to trust the database if there are certificates marked ```-t```.)   |
| ```-u usage```        | 0=SSL client, 1=SSL server, 2=SSL StepUp, 3=SSL CA, 4=Email signer, 5=Email recipient, 6=Object signer, 9=ProtectedObjectSigner, 10=OCSP responder, 11=Any CA                                                                            |
| ```-o oid```          | Set policy OID for cert validation.                                                                                                                                                                                                      |
| ```-g test-type```    | Sets status checking test type. Possible values are "leaf" or "chain".                                                                                                                                                                   |
| ```-h test-flags```   | Sets revocation flags for the test type it follows. Possible flags: "testLocalInfoFirst" and "requireFreshInfo".                                                                                                                         |
| ```-m method-type```  | Sets method type for the test type it follows. Possible types are "crl" and "ocsp".                                                                                                                                                      |
| ```-s method-flags``` | Sets revocation flags for the method it follows. Possible types are "doNotUse", "forbidFetching", "ignoreDefaultSrc", "requireInfo" and "failIfNoInfo".                                                                                  |

The following certificate purposes are supported by the ```vfychain``` tool via the ```-u <usage>``` option:

| Purpose                  | Code        |
| :---                     |    :----:   |
| SSL Client               | ```0```     |
| SSL Server               | ```1```     |
| SSL Step-Up              | ```2```     |
| SSL CA                   | ```3```     |
| Email Signer             | ```4```     |
| Email Recipient          | ```5```     |
| Object Signer            | ```6```     |
| Protected Object Signer  | ```9```     |
| OCSP Responder           | ```10```    |
| Any CA                   | ```11```    |

To validate a certificate contained in a NSS database, you can use the ```certutil``` command. For example, to test the certificate with friendly name ```test_cert``` for e-mail signing, you could run:
```bash
certutil -V -n "test_cert" -u S -e -l -d /path/to/nssdb
```

The following certificate purposes are supported by the ```certutil``` tool via the ```-u <purpose>``` option:

| Purpose         | Code        |
| :---            | :----:      |
| SSL Client      | ```C```     |
| SSL Server      | ```V```     |
| SSL CA          | ```L```     |
| Any CA          | ```A```     |
| Verify CA       | ```V```     |
| Email Signer    | ```S```     |
| Email Recipient | ```R```     |
| OCSP Responder  | ```O```     |
| Object Signer   | ```J```     |

## Golang
Golang uses its own implementation for [X.509](https://www.itu.int/itu-t/recommendations/rec.aspx?rec=X.509) certificate validation.

The following enumeration defines the EKU usage codes Golang uses internally:
```plain
ExtKeyUsageServerAuth = 1
ExtKeyUsageClientAuth = 2
ExtKeyUsageCodeSigning = 3
ExtKeyUsageEmailProtection = 4
ExtKeyUsageIPSECEndSystem = 5
ExtKeyUsageIPSECTunnel = 6
ExtKeyUsageIPSECUser = 7
ExtKeyUsageTimeStamping = 8
ExtKeyUsageOCSPSigning  = 9
ExtKeyUsageMicrosoftServerGatedCrypto = 10
ExtKeyUsageNetscapeServerGatedCrypto = 11
ExtKeyUsageMicrosoftCommercialCodeSigning = 12
ExtKeyUsageMicrosoftKernelCodeSigning = 13
```

## GnuTLS
The ```certtool``` utility provided by GnuTLS can be used to validate certificates.

Note that ```certtool``` version below ```3.0.0``` do not support certificate validation.

To display a certificate:
```bash
cat /path/to/cert.crt \
  | certtool -d 9999 \
    --certificate-info \
    --load-ca-certificate /path/to/ca/chain.pem
```

To verify a certificate:
```bash
cat /path/to/cert.crt \
  | certtool -d 9999 \
    --verify \
    --load-ca-certificate /path/to/ca/chain.pem
```

To verify a particular purpose, include the OID using the ```--verify-purpose <oid>``` option. For example:
```bash
cat /path/to/cert.crt \
  | certtool -d 9999 \
    --verify \
    --verify-hostname test.example.com \
    --verify-purpose 1.3.6.1.5.5.7.3.1 \
    --load-ca-certificate /path/to/ca/chain.pem
```

To verify a certificate chain:
```bash
cat /path/to/chain.pem | certtool --verify-chain
```

Note that you can use ```--infile <file>``` instead of piping the certificate to ```certtool```. The debug level can be between 0-9999, and controls how much debugging output is printed out.

## Technical Constraints
For a certificate to be technically constrained, it *MUST* contain an ```extendedKeyUsage``` extension defining the purposes for which it may be used. When an EKU extension is added to a Subordinate CA, the CA is restricted in which purposes it may issue certificates for.

According to the [CA/Browser Forum Baseline Requirements, section 7.1.5](https://github.com/cabforum/documents/blob/master/docs/BR.md#715-name-constraints):
  > If the Subordinate CA Certificate includes the id-kp-serverAuth extended key usage, then the Subordinate CA Certificate MUST include the Name Constraints X.509v3 extension with constraints on dNSName, iPAddress and DirectoryName.

The [Mozilla Root Store Policy, section 5.3](https://github.com/mozilla/pkipolicy/blob/master/rootstore/policy.md#53-intermediate-certificates) states the following:
  > Intermediate certificates created after January 1, 2019, with the exception of cross-certificates that share a private key with a corresponding root certificate:
  > -   *MUST* contain an EKU extension; and,
  > -   *MUST NOT* include the ```anyExtendedKeyUsage``` KeyPurposeId; and,
  > -   *MUST NOT* include both the ```id-kp-serverAuth``` and ```id-kp-emailProtection``` KeyPurposeIds in the same certificate.

The [Mozilla Root Store Policy, section 5.3.1](https://github.com/mozilla/pkipolicy/blob/master/rootstore/policy.md#531-technically-constrained) states:
  > -   If the certificate includes the ```id-kp-serverAuth``` extended key usage, then to be considered technically constrained, the certificate *MUST* be Name Constrained.
  > -   If the certificate includes the ```id-kp-emailProtection``` extended key usage, then to be considered technically constrained, it *MUST* include the Name Constraints X.509v3 extension with constraints on ```rfc822Name```, with at least one name in ```permittedSubtrees```, each such name having its ownership validated according to [section 3.2.2.4 of the Baseline Requirements](https://github.com/cabforum/documents/blob/master/docs/BR.md#3224-validation-of-domain-authorization-or-control).
  > -   The ```anyExtendedKeyUsage``` KeyPurposeId *MUST NOT* appear within the EKU extension.

## Federal PKI Standards
You can use the online [Federal PKI X.509 certificate linter](https://cpct.app.cloud.gov/) webapp to validate certificates against U.S. Federal PKI standards.

The source code for the webservice is provided in the [fpkilint](https://github.com/GSA/fpkilint) GitHub repository.

## Lint module notes
-   The ```gs-certlint`` module currently requires either a dnsName or ipAddress for ```subjectAltName``` on Extended-Validation (EV) certificates. This may not be the correct behavior, as EV code-signing certificates may be issued to an individual. More research is needed.

## References
Relevant source code repositories are listed below:
-   [OpenSSL](https://github.com/openssl/openssl)
-   [GnuTLS](https://gitlab.com/gnutls/gnutls)
-   [Mozilla NSS](https://dxr.mozilla.org/mozilla-central/source/security/nss) ([GitHub Mirror](https://github.com/nss-dev/nss))
-   [Mozilla TLS Observatory](https://github.com/mozilla/tls-observatory)
-   [Golang](https://github.com/golang/go)
-   [certigo Go certificate tool](https://github.com/square/certigo)
-   [cert Go certificate tool](https://github.com/genkiroid/cert)
-   [certvalidator Java X.509 Validator](https://github.com/difi/certvalidator)
-   [Google Certificate Transparency](https://github.com/google/certificate-transparency)
-   [Google Certificate Transparency: Go Code](https://github.com/google/certificate-transparency-go)
-   [Federal PKI X.509 certificate linter](https://github.com/GSA/fpkilint)
-   [zmap/zcrypto: x509/extended_key_usage.go](https://github.com/zmap/zcrypto/blob/master/x509/extended_key_usage.go)

The following resources provide relevant standards documentation and examples for PKI testing:
-   [ITU-T X.509](https://www.itu.int/itu-t/recommendations/rec.aspx?rec=X.509)
-   [NIST Public Key Infrastructure Testing](https://csrc.nist.gov/projects/pki-testing)
-   [Mozilla Root Store Policy](https://github.com/mozilla/pkipolicy/blob/master/rootstore/policy.md)
-   [Mozilla PKI Project](http://mozilla.org/projects/security/pki/)
-   [Mozilla Developer Network: Network Security Services (NSS)](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS)
-   [Mozilla Developer Network: NSS Tools certutil](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Tools/certutil)
-   [Mozilla Developer Network: NSS Tools vfychain](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Tools/vfychain)
-   [CA/Browser Forum: Baseline Requirements](https://github.com/cabforum/documents/blob/master/docs/BR.md)
-   [CA/Browser Forum: Extended-Validation Guidelines](https://github.com/cabforum/documents/blob/master/docs/EVG.md)
-   [U.S. Federal Public Trust TLS Certificate Policy](https://devicepki.idmanagement.gov/) ([GitHub](https://github.com/uspki/policies))
-   [RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://tools.ietf.org/html/rfc5280)
-   [RFC 6960: X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP](https://tools.ietf.org/html/rfc6960)
-   [RFC 4158: Internet X.509 Public Key Infrastructure: Certification Path Building](https://tools.ietf.org/html/rfc4158)
-   [RFC 5913: Clearance Attribute and Authority Clearance Constraints Certificate Extension](https://tools.ietf.org/html/rfc5913)
-   [RFC 5055: Server-Based Certificate Validation Protocol (SCVP)](https://tools.ietf.org/html/rfc5055)
-   [RFC 6962: Certificate Transparency](https://tools.ietf.org/html/rfc6962)
-   [Go Programming Language: x509 Package](https://golang.org/pkg/crypto/x509/)
-   [Certificate Transparency](http://www.certificate-transparency.org/) ([GitHub](https://github.com/google/certificate-transparency))
-   [Certificate Transparency Log Policy](https://github.com/chromium/ct-policy/blob/master/log_policy.md#certificate-transparency-log-policy)
-   [Certificate Transparency RFC](https://github.com/google/certificate-transparency-rfcs)
-   [Microsoft Support: Object IDs associated with Microsoft cryptography](https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography)
-   [Windows Dev Center: Supported Extensions](https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/supported-extensions)
-   [Windows Dev Center: IX509ExtensionEnhancedKeyUsage](https://docs.microsoft.com/en-us/windows/desktop/api/CertEnroll/nn-certenroll-ix509extensionenhancedkeyusage)
