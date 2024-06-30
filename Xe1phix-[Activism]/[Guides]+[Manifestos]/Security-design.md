## Overview

To provide its security properties, TFC's hardware and software designs differ from currently existing messaging systems. As the design choices may at times appear inconvenient or overly complicated, this document explains the rationale behind them in detail and compares TFC's protocol against the current state-of-the-art protocols such as the Signal protocol.


## The issue of endpoint security

All programs, from secure messaging apps to operating systems, are written by imperfect humans. As writing a [formal proof of correctness for even the simplest application is a practical impossibility](https://media.ccc.de/v/36c3-10893-high-assurance_crypto_software#t=2326), all programs should be assumed to contain bugs. These bugs can sometimes compromise the security of the system passively (due to eventual erroneous behavior), or they can introduce vulnerabilities that can be exploited by attackers with malicious inputs.

All proper end-to-end encrypted (E2EE) messaging systems store private key(s) exclusively on the user's device (endpoint). The holy grail of attacks against E2EE systems is called [exfiltration](https://en.wikipedia.org/wiki/Data_theft) where the sensitive data, namely the private keys or plaintext messages, are stolen from the endpoint. The attack is directed against the target system's [trusted computing base (TCB)](https://en.wikipedia.org/wiki/Trusted_computing_base), which is defined as the set of all parts that are critical to the security of that system. The overwhelming majority of TCBs are connected to the network and compromising them with polished malware that exploits a [zero-day vulnerability](https://en.wikipedia.org/wiki/Zero-day_(computing)), is trivial and undetectable.

![](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/1_networked_tcb.png)
[Networked TCB](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/1_networked_tcb.png)

Depending on the protocol design of the messaging system, the exfiltrated private key can be leveraged in a number of passive and active attacks that allow decryption of messages in transit.

A messaging program cannot protect the user by itself. Even if it was somehow perfectly written, it is only a small part of the entire software stack: by compromising, for example, a more trusted part of the operating system, all security the messaging tool can provide is lost. The only way to ensure sensitive data cannot be stolen from the endpoint is to patch all vulnerabilities in all of the programs that the networked TCB consists of. Since this is a practical impossibility, it is usually mitigated with personal security products (PSPs). However, nation-state actors have been found to test their malware is not detected by such utilities. 

>The [requirement list](https://wikileaks.org/ciav7p1/cms/page_12353654.html) of the [CIA's] Automated Implant Branch (AIB) for Grasshopper puts special attention on [PSP avoidance](https://wikileaks.org/ciav7p1/cms/page_14587218.html), so that any Personal Security Products like 'MS Security Essentials', 'Rising', 'Symantec Endpoint' or 'Kaspersky IS' on target machines do not detect Grasshopper elements. [Source](https://wikileaks.org/vault7/#Grasshopper)

As software has its limitations, hardware-based systems have been designed to provide more robust security.


### Moving cryptographic operations and key management to secure environment

One attempt to provide security against exfiltration is to generate and store keys, and handle cryptographic operations on a [secure cryptoprocessor](https://en.wikipedia.org/wiki/Secure_cryptoprocessor) of a smart card or a [hardware security module (HSM)](https://en.wikipedia.org/wiki/Hardware_security_module). These systems have rigorous security design that reduces the number of vulnerabilities significantly. For example, Google has introduced a prototype for secure messaging with micro-SD card shaped smart card called [Project Vault](https://www.businessinsider.com/googles-project-vault-for-secret-messages-2015-5?r=US&IR=T&IR=T). This is great in the sense that sensitive keys stay protected and in that cryptographic operations can be trusted during runtime. However, despite best efforts by companies, it is practically impossible to verify there are no vulnerabilities, that governments have not [coerced the company to insert backdoors](https://www.reuters.com/article/us-usa-security-rsa-idUSBRE9BJ1C220131220) or that government agencies do not [replace products shipped to customers](https://arstechnica.com/tech-policy/2014/05/photos-of-an-nsa-upgrade-factory-show-cisco-router-getting-implant/). The major issue is, even if the design of the smart card is perfect in every aspect, it does not guarantee the confidentiality of communication: 

![](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/2_reduced_tcb.png)
[Reduced TCB](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/2_reduced_tcb.png)

Plaintext messages are still written using a keyboard connected to the insecure host computer. Thus, if an attacker has compromised the operating system and planted, e.g., a kernel or API-based keylogger and screenlogger, plaintext messages can be accessed before encryption and after decryption. Malware can exfiltrate messages in real time, or cache them for later exfiltration. So, while smart cards and HSMs are excellent, e.g., when creating digital signatures, they are not the solution for secure messaging.


### Moving cryptographic operations, key management, and plaintext handling to an air-gapped system

For high-security communication, the general recommendation is to use something like 
[PGP](http://curtiswallen.com/pgp/) 
[on](https://www.youtube.com/watch?v=D_xrlAGzQfs) 
[an](https://www.schneier.com/blog/archives/2013/10/air_gaps.html) 
[air-gapped](https://thetinhat.com/tutorials/misc/security-tools-journalists.html) 
[system](https://blog.cryptographyengineering.com/2013/03/here-come-encryption-apps.html), 
which is a significant improvement over smart cards, as the entire TCB, including plaintext i/o, is moved to a computer that can not be reached from the network directly. 

The main issue in this approach is, however, the window of opportunity for malware to jump over the air-gap never closes.

The rough overview of the attack is as follows: The attacker first exploits the networked computer with sophisticated malware. Then, the first time an encrypted message is received from a contact, the malware spreads to the air-gapped computer via the ciphertext transmission media, e.g., a thumb drive. The next time a message is sent to the contact, the malware covertly exfiltrates the private key and all captured keystrokes (including the password that protects the private key) using the transmission media to the networked computer, from where they are forwarded to the attacker in the network.

![](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/3_airgapped_tcb.png)
[Air-gapped TCB](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/3_airgapped_tcb.png)

The primary tool for air-gapped messaging has always been PGP which is problematic as it lacks forward secrecy: Once the private RSA key has been exfiltrated, all past and future messages protected by the key can be decrypted passively. While no examples of malware specifically targeting PGP have yet been found, some malware such as [Stuxnet have already demonstrated the capability to jump over air-gaps](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=7122176) and [the NSA's modular payload UNITEDRAKE has plugins called SALVAGERABBIT and GROK](https://theintercept.com/2014/03/12/nsa-plans-infect-millions-computers-malware/) that enable the attacker to exfiltrate files and log keystrokes. The NSA has also devised [implants](https://www.schneier.com/blog/archives/2014/02/somberknave_nsa.html) for jumping over air-gaps.


### Expanding on the idea of air-gaps

A simple air-gap is clearly not enough. However, by carefully evaluating each step of the previous example in isolation, a way to secure the endpoint becomes apparent:

1. The TCB on the air-gapped computer of the sender remains clean (which is not the same as invulnerable -- it simply means "not infected") as long as ciphertexts are only exported, and a clean (=separate, never before used) removable media is used every time, and the old media is destroyed immediately after use.

2. If the air-gapped computer of the recipient only receives ciphertexts from the network, an arbitrary number of ciphertexts can be imported to the air-gapped computer. As long as the used removable media is immediately destroyed after the ciphertext has been imported, no malware that propagates to the air-gapped receiver computer has a return channel it can use to exfiltrate keys or plaintexts.

![](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/4_single_unidirectional_usb.png)
[Exfiltration secure communication in single direction](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/4_single_unidirectional_usb.png)

The problem of this two computers per endpoint -approach is however that messages can be only sent in one direction. However, by nature, human communication is bidirectional. The significant discovery and core idea of TFC is the realization that a separate set of computers can be added for replies... 

![](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/5_dual_unidirectional_usb.png)
[Bidirectional exfiltration secure communication](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/5_dual_unidirectional_usb.png)

...and that since the networked computers of the return channel can also be assumed to be compromised, a duplicate networked computer is not needed. The solution, therefore, is for each endpoint to have three separate computers: A split TCB where one computer only outputs ciphertexts, and another only receives ciphertexts. The third computer acts as a protocol converter that relays ciphertexts between the user's unidirectionally connected computers, and the network.


![](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/6_combined_unidirectional_usb.png)
[Unified Networked Computers for endpoint](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/6_combined_unidirectional_usb.png)

To make the split TCB suitable for real-time instant messaging, removable media must be replaced with a unidirectional data transmission link that relies on asynchronous data transmission over protocols such as the UDP or UART. However, how is the unidirectionality guaranteed? Running only a listener program on the receiver computer is not high assurance: malware that propagates to that system can trivially add sender functionality to establish a return channel. The answer is to remove the return channel on the hardware level. However, features such as [auto MDI-X](https://en.wikipedia.org/wiki/Medium-dependent_interface) make it impossible to enforce unidirectional UDP transmission over Ethernet. A simpler transmission protocol is required, and for that, UART with TTL or RS232 voltages fits perfectly.


##### Trust but verify

Unlike bit-banged serial communication over GPIO, UART chips most likely have more than just rule-based limitations on Tx and Rx pin assignment. However, more assurance should be sought. Unidirectionality of communication can be guaranteed with a simple hardware device called **data diode** that is placed in-between the sending and receiving UART interfaces. Data diode is a device that takes advantage of the fundamental laws of physics to limit the direction of data flow. The data diode used in TFC is a slight modification to [the design by the pseudonym Sancho P](https://imgur.com/a/5Cv19). (Earlier data diode designs are based on [the paper by Douglas W. Jones and Tom C. Bowersox on RS232 data diodes](https://homepage.divms.uiowa.edu/~jones/voting/diode/evt06paper.pdf).)

![](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/7_data_diode_circuit.jpg)
[Data diode circuit diagram](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/7_data_diode_circuit.jpg)

![](https://www.cs.helsinki.fi/u/oottela/wiki/readme/data_diode.jpg)
[Completed data diode](https://www.cs.helsinki.fi/u/oottela/wiki/readme/data_diode.jpg)

This data diode makes use of two optocouplers, each with two transducers that form a unidirectional gateway. On the sender side, depending on whether the output bit is one or zero, the high or low signal from the FT232R UART interface's Tx-pin turns the LED inside the HCPL-7723 optocoupler on or off. The state of the LED is detected by the optocoupler's photodiode, and the reproduced signal is then amplified by the optocoupler's [TIA](https://en.wikipedia.org/wiki/Transimpedance_amplifier) and the signal is finally fed into the Rx-pin of the receiving UART interface.

This optical gap is guaranteed to be one way because while LEDs show a weak [photoelectric effect](https://en.wikipedia.org/wiki/Photoelectric_effect), photodiodes (excluding Ternary and quaternary GaAsP photodiodes) do not emit light when current passes through them.

The hardware configuration that combines the data diodes with split TCB has impressive security guarantees. It sets a one-time price tag on endpoint security. As long as the Source Computer (transmitter) doesn't output sensitive data (due to programming error or pre-existing malware), the entire system remains secure against **remote** key and plaintext exfiltration with malware. The malware cannot propagate from Networked Computer to Source Computer, and malware that propagates from Networked Computer to Destination Computer (receiver) is unable to exfiltrate data back to Networked Computer.

![](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/8_split_tcb2.png)
[Split TCB](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/8_split_tcb2.png)

The data diodes in the illustration above are denoted with the standard diode symbol: Data can flow through them in the forward direction (indicated by the triangle-shaped arrowhead), but not in the reverse direction. The puzzled invader represents malware/attacker unable to achieve it's goal, that is, propagate further and/or access sensitive content.


## Security overview and roles of TFC computers

#### Source Computer

Source Computer runs the TFC Transmitter Program that reads input from the user and based on that, encrypts, signs and outputs messages/files/commands. By design, Source Computer requires the capability to output data to the network. As malware could use the same channel to output sensitive keys and plaintexts covertly, the computer has an absolute requirement of remaining clean. 

During TFC setup, Source Computer has the same amount of security against infection as all standard end-to-end encrypted messaging systems have throughout their use. Setup of TFC on Source Computer, therefore, introduces a race hazard that ends after the installer has downloaded all dependencies and programs, and disconnected the Source Computer from the network. If the Source Computer was not infected at this point, the security properties of Source Computer's `alternative data diode model` take effect: The data diode prevents all inbound traffic and permanently protects the Source Computer from remote compromise. Source Computer is the only device to have such property, and therefore, it is the only device trusted to generate private keys for communication (and to give trustworthy advice to the user during operation).

All devices that are bidirectionally connected to the Source Computer need to form their own, closed ecosystem. The devices must never be connected to less secure computers. For example, a journalist who wishes to send photos to the newsroom, should only connect the memory card of the camera to their Source Computer. Any physical documents to be sent should be scanned with a scanner dedicated to the Source Computer. 


#### Destination Computer

Destination Computer runs the TFC Receiver Program that authenticates, decrypts and processes messages, files and commands it receives through its serial interface and the data diode. Destination computer makes use of the security properties of the `classical data diode model` that ensures any infiltrating malware is unable to exfiltrate sensitive keys/plaintexts from the computer. All received packets are encrypted and signed with XChaCha20-Poly1305, thus the adversary is unable to inject packets even if they compromise the Networked Computer. Because Destination Computer must by design receive data from the network, and because serial interface's software stack (including the driver and the PySerial library) is with overwhelming probability not invulnerable, a determined attacker can with high probability (i.e., they are assumed to be able to) execute arbitrary code on Destination Computer. Because of this, the Receiver Program is not trusted to contribute to TFC's communication key generation: the private key or the entropy used to produce it might have been sent in by the attacker, and that would completely break the security of the system.

Destination Computer and any devices connected to it should also form a closed ecosystem. Data received by, e.g., a newsroom can be copied across computers with same security level using (wired) local network. The computers in the LAN must take same precautions regarding connectivity and covert exfiltration channels as the Destination Computer. The surface area of key exfiltration attacks can be reduced if all received documents are exported from the Destination Computer directly using a dedicated printer before they are re-scanned to less secure systems.


#### Networked Computer

TFC is designed with the assumption the Networked Computer is compromised by an attacker immediately. The Relay Program running on the Networked Computer only relays contact requests, X448 public keys, group management messages, and signed ciphertexts. Compromise of this system is not different from a compromised email-server routing PGP-ciphertexts: Networked Computer is not part of the TCB, it is part of the ciphertext routing network.

There is, however, a lot more to security than just confidentiality of content. Networked Computer is problematic in terms of anonymity and metadata: If the device is compromised, any files, hardware IDs, public IP addresses and data collected by sensors such as webcams, microphones and Wi-Fi interfaces that can be attributed to the user, can reveal the user's real-life identity to the attacker.


## Cryptographic design

### Modern algorithms

TFC uses 256-bit [XChaCha20](https://cr.yp.to/chacha/chacha-20080128.pdf)-[Poly1305](https://cr.yp.to/mac/poly1305-20050329.pdf) authenticated encryption to protect all communication and persistent data. Symmetric keys are either
[pre-shared](https://en.wikipedia.org/wiki/Pre-shared_key),
or exchanged using
[X448](https://eprint.iacr.org/2015/625.pdf),
the base-10
[fingerprints](https://en.wikipedia.org/wiki/Public_key_fingerprint)
of which are verified via out-of-band channel. TFC provides per-message
[forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy)
with
[Blake2b](https://blake2.net/blake2.pdf)
based
[hash ratchet](https://www.youtube.com/watch?v=9sO2qdTci-s#t=1m34s).
Except for transmitted files, all variable length data is padded before encryption to hide plaintext length. All persistent TFC data is encrypted locally using XChaCha20-Poly1305, the key of which is derived from 
password and a 256-bit salt using 
[Argon2id](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf).
Keys and nonces are generated with Linux kernel's getrandom() syscall that draws entropy from its ChaCha20 based CSPRNG.

Each algorithm listed above is state-of-the-art (read: best possible choice) as per modern standards. Below is a more detailed dissection of each primitive.

<details>
    <summary><b>X448</b></summary>


X448 is the Diffie-Hellman function for Curve448-Goldilocks, a state-of-the-art elliptical curve published by Mike Hamburg in 2014.

For more details, see
* https://eprint.iacr.org/2015/625.pdf
* http://ed448goldilocks.sourceforge.net/
* https://en.wikipedia.org/wiki/Curve448

The reasons for using X448 in TFC include

* Curve448 meets the criterion for a [SafeCurve](https://safecurves.cr.yp.to/):

  * Parameters

    - Use of large prime field (p = 2<sup>448</sup> - 2<sup>224</sup> - 1).

    - The Edwards curve (x<sup>2</sup>+y<sup>2</sup> = 1-39081x<sup>2</sup>y<sup>2</sup>) is complete.

    - The base point (x<sub>1</sub>,y<sub>1</sub>) is on the curve.

  * ECDLP security

     - 222.8-bit security against the Pollard's rho method. This is important as the security of hash ratchet depends on the security of the root key. Curve25519 is thus less feasible choice. Curve448 is also likely to resist quantum computers and mathematical breakthroughs against ECC for a longer time.
    
     - Safe against additive and multiplicative transfer.
    
     - The complex-multiplication field discriminant is 2<sup>447.5</sup>, which is much larger than the required minimum (2<sup>100</sup>).
    
    - The curve-generation process is fully rigid, i.e. it has been completely explained. In comparison, NIST P-curves use coefficients generated by hashing unexplained seeds.

  * ECC security

    - Use of Montgomery ladder that protects from side channel attacks by doing constant-time single-scalar multiplication.

    - 221.8-bit security against twist attacks (small-subgroup attack combined with invalid-curve attack).

    - Support for complete single-scalar and multi-scalar multiplication formulas.

    - Points on Curve448 (e.g. public keys) are indistinguishable from uniform random strings.

* Safer curves (M-511 and E-521) do not have robust implementations.

* NIST has [announced](https://csrc.nist.gov/News/2017/Transition-Plans-for-Key-Establishment-Schemes) X448 will be included in the SP 800-186.

* Its public keys do not require validation as long as the resulting shared secret is not zero:

  >[X448] is actually two curves, where any patterns of bits
   will be interpreted as a point on one of the curves or on the
   other. [[Source](https://crypto.stackexchange.com/a/44348)]

*  Its public keys are reasonably short (84 chars when WIF-encoded) to be manually typed from Networked Computer to Source Computer.

The X448 implementation used is the [OpenSSL implementation](https://github.com/openssl/openssl/tree/OpenSSL_1_1_1-stable/crypto/ec/curve448) (that [is based on the original work by Mike Hamburg](https://github.com/openssl/openssl/pull/4829#issue-155926460)), and its [Python bindings](https://github.com/pyca/cryptography/blob/master/src/cryptography/hazmat/primitives/asymmetric/x448.py) in the [pyca/cryptography](https://github.com/pyca/cryptography) library.

The correctness of the X448 implementation is tested by TFC unit tests. The testing is done in limited scope by using the [official test vectors](https://tools.ietf.org/html/rfc7748#section-6.2).
</details>


<details>
    <summary><b>XChaCha20-Poly1305</b></summary>

ChaCha20 is a stream cipher published by [Daniel J. Bernstein](https://en.wikipedia.org/wiki/Daniel_J._Bernstein) (djb) in 2008. The algorithm is an improved version of Salsa20 -- another stream cipher by djb -- selected by ECRYPT into the eSTREAM portfolio in 2008. The improvement in question is, ChaCha20 increases the per-round diffusion compared to Salsa20 while maintaining or increasing speed.

For more details, see
* https://cr.yp.to/chacha.html
* https://cr.yp.to/snuffle.html
* https://cr.yp.to/snuffle/security.pdf
* https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant

The Poly1305 is a Wegman-Carter message authentication code (MAC) also designed by djb. The MAC is provably secure if ChaCha20 is secure. The 128-bit tag space ensures the attacker's advantage to create an existential forgery is negligible.
 
For more details, see
* https://cr.yp.to/mac.html

The version used in TFC is the [XChaCha20-Poly1305-IETF](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-01), a variant of the ChaCha20-Poly1305-IETF ([RFC 8439](https://tools.ietf.org/html/rfc8439)). Quoting [libsodium](https://download.libsodium.org/doc/secret-key_cryptography/aead/chacha20-poly1305#variants), the XChaCha20 (=eXtended-nonce ChaCha20) variant allows encryption of ~2<sup>64</sup> bytes per message, encryption of practically unlimited number of messages, and safe use of random nonces due to the 192-bit nonce space.

The reasons for using XChaCha20-Poly1305 in TFC include

* Conservative 256-bit [key size](https://cr.yp.to/snuffle/keysizes.pdf) that matches the 222.8-bit security of X448, and BLAKE2b (with truncated, 256-bit hashes).

* The Salsa20 algorithm has 14 years of [cryptanalysis](https://en.wikipedia.org/wiki/Salsa20#Cryptanalysis_of_Salsa20) behind it and ChaCha20 has resisted cryptanalysis as well [[1](https://eprint.iacr.org/2007/472.pdf), [2](https://eprint.iacr.org/2015/698.pdf)]. Currently the [best public attack](https://eprint.iacr.org/2016/377.pdf) breaks ChaCha7 in 2<sup>233</sup> operations.

* Security against differential and linear cryptanalysis [[1](https://www.cryptrec.go.jp/exreport/cryptrec-ex-2601-2016.pdf), [2](https://eprint.iacr.org/2013/328.pdf)].

* Security against cache-timing attacks on all CPUs (unlike AES on CPUs without AES-NI).[[p. 2]](https://cr.yp.to/antiforgery/cachetiming-20050414.pdf)

* The [increased diffusion](https://cr.yp.to/chacha/chacha-20080128.pdf) over the well-received Salsa20.

* The algorithm is [much faster](https://cr.yp.to/chacha/chacha-20080128.pdf) compared to AES (in cases where the CPU and/or implementation does not support AES-NI).

* [The good name of djb](https://www.eff.org/sv/deeplinks/2015/04/remembering-case-established-code-speech).

The XChaCha20-Poly1305 IETF implementation used is the 
[libsodium implementation](https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c) and its [Python bindings](https://github.com/pyca/pynacl/blob/master/src/nacl/bindings/crypto_aead.py) in the 
[pyca/PyNaCl](https://github.com/pyca/pynacl) library.

The correctness of the implementation is tested by TFC unit tests. The testing is done in limited scope by using the [libsodium](https://github.com/jedisct1/libsodium/blob/master/test/default/aead_xchacha20poly1305.c) and official [IETF test vectors](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-01#appendix-A.1).
</details>

<details>
    <summary><b>BLAKE2b</b></summary>

BLAKE2 is the successor of SHA3-finalist BLAKE*, designed by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein. The hash function is based on the ChaCha stream cipher, designed by djb.

*BLAKE was designed by Jean-Philippe Aumasson, Luca Henzen, Willi Meier, and Raphael C.-W. Phan.

For more details, see
* https://blake2.net/
* https://tools.ietf.org/html/rfc7693.html
* https://docs.python.org/3.7/library/hashlib.html#blake2

The reasons for using BLAKE2b in TFC include

* According to NIST [[p. 13]](https://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf) BLAKE [received](https://blake2.net/#cr) more in-depth cryptanalysis than Keccak (SHA3):

    > Keccak received a significant amount of cryptanalysis,
   although not quite the depth of analysis applied to BLAKE,
   Grøstl, or Skein.

* BLAKE shares design elements with SHA-2 that has 11 years of
  [cryptanalysis](https://en.wikipedia.org/wiki/SHA-2#Cryptanalysis_and_validation) behind it.

* 128-bit collision/preimage/second-preimage resistance against Grover's algorithm running on a quantum Turing machine.

* The [implementation](https://github.com/python/cpython/tree/3.7/Modules/_blake2) of the algorithm is bundled in Python3.7's hashlib.

* Compared to SHA3-256, the algorithm runs faster on CPUs which means better hash ratchet performance.

    > The ARX-based algorithms, BLAKE and Skein, perform extremely well in software. [[p. 13]](https://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf)

* Compared to SHA3-256, the algorithm runs slower on ASICs which means attacks by high-budget adversaries are slower.

    > Keccak has a clear advantage in throughput/area performance in hardware implementations. [[p. 13]](https://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf)

Note that while the default digest length of BLAKE2b (the implementation optimized for AMD64 systems) is 512 bits, the digest length is truncated to 256 bits for the use in TFC.

The correctness of the BLAKE2b implementation [[1](https://github.com/python/cpython/tree/3.7/Modules/_blake2), [2](https://github.com/python/cpython/blob/3.7/Lib/hashlib.py)] is tested by TFC unit tests. The testing is done with the complete suite of [BLAKE2b known answer tests (KATs)](https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2b-kat.txt).
</details>

<details>
    <summary><b>Argon2</b></summary>

Argon2 is a password hashing function designed by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich from the University of Luxembourg. The algorithm is the winner of the 2015 Password Hashing Competition (PHC).

For more details, see
* https://password-hashing.net/
* https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf 
* https://en.wikipedia.org/wiki/Argon2

The reasons for using Argon2 in TFC include

* PBKDF2 and bcrypt are not memory-hard, thus they are weak against massively parallel computing attacks with FPGAs/GPUs/ASICs [[p. 2]](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf).

* scrypt is very complex as it "combines two independent cryptographic primitives (the SHA256 hash function, and the Salsa20/8 core operation), and four generic operations (HMAC, PBKDF2, Block-Mix, and ROMix)." [[p. 10]](https://password-hashing.net/submissions/specs/Catena-v5.pdf) Furthermore, scrypt is "vulnerable to trivial time-memory trade-off (TMTO) attacks that allows compact implementations with the same energy cost." [[p. 2]](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf)

* Of all of the PHC finalists, only Catena and Argon2i offer complete cache-timing resistance by using data-independent memory access. Catena does not support parallelism [[p. 49]](https://password-hashing.net/submissions/specs/Catena-v5.pdf), thus if it later turns out TFC needs stronger protection from cache-timing attacks, the selection of Argon2 (that always supports parallelism) is ideal, as switching from Argon2id to Argon2i is trivial.

* More secure algorithms such as the [Balloon hash function](https://crypto.stanford.edu/balloon/) do not have robust implementations.

The purpose of Argon2 is to stretch a password into a 256-bit key. Argon2 features a slow, memory-hard hash function that consumes computational resources of an attacker that attempts a dictionary or a brute force attack.
 
The function also takes a salt (256-bit random value in this case) that prevents rainbow-table attacks, and forces each attack to take place against an individual (physically compromised) TFC-endpoint, or PSK transmission media.
 
The Argon2 version used is the Argon2id, that is the current recommendation of the [draft RFC](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-06#section-9.4). Argon2id uses data-independent memory access for the first half of the first iteration, and data-dependent memory access for the rest. This provides a lot of protection against TMTO attacks which is great because most of the expected attacks are against physically compromised data storage devices where the encrypted data is at rest. Argon2id also adds some security against side-channel attacks that malicious code injected to the Destination Computer might perform. Considering these two attacks, Argon2id is the most secure
choice.

The implementation of Argon2 used in TFC is the [argon2_cffi](https://github.com/hynek/argon2_cffi) that provides C-bindings for the algorithm's [reference C implementation](https://github.com/P-H-C/phc-winner-argon2).

The correctness of the implementation is tested by TFC unit tests. The testing is done by comparing the output of the `argon2_cffi` library with the output of the Argon2 reference command-line utility under randomized input parameters.
</details>

<details>
    <summary><b>Strong random numbers: Linux-RNG</b></summary>

All cryptographic values (keys, nonces, and salts) are generated by the Linux kernel's modern, ChaCha20-based cryptographically secure pseudo-random number generator (CSPRNG), also known as the Linux-RNG, or LRNG.

For more details, see
* https://www.2uo.de/myths-about-urandom/
* https://www.chronox.de/lrng/doc/lrng.pdf
* https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/LinuxRNG/LinuxRNG_EN.pdf?__blob=publicationFile&v=16
* https://github.com/torvalds/linux/blob/master/drivers/char/random.c


#### TFC key generation overview

The following schematic of the LRNG and its relation to TFC is based
on [[**BSI p.19**]](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/LinuxRNG/LinuxRNG_EN.pdf?__blob=publicationFile&v=16). (Note: the page number for the BSI report is always the PDF page number, not the printed page number in the bottom margin of each page. This makes searching of the citations faster.)

                X448 private keys          Other TFC keys
                        ↑                         ↑
                 OS random engine          BLAKE2b (by TFC)
                        ↑                         ↑
                        └────────┐       ┌────────┘
                                GETRANDOM()
                                     ↑
                                     |  ┌────────┐
                                     |  |        | State transition
                             ┏━━━━━━━━━━━━━━━┓   |
                             ┃ ChaCha20 DRNG ┃<──┘
                             ┗━━━━━━━━━━━━━━━┛
                                     ↑
                                   fold
                                     ↑
                                   SHA-1 ────────┐
                                     ↑           | State transition
                             ┏━━━━━━━━━━━━━━┓    |
                             ┃  input_pool  ┃<───┘
                             ┗━━━━━━━━━━━━━━┛<─────────────────────┐
                               ↑ ↑       ↑                         |
          ┌────────────────────┘ |    ┏━━━━━━━━━━━━━━━┓            |
          |              ┌───────┘    ┃ Time variance ┃      ┏━━━━━━━━━━━┓
          |              |            ┃  calculation  ┃      ┃ fast_pool ┃
          |              |            ┗━━━━━━━━━━━━━━━┛      ┗━━━━━━━━━━━┛
          |              |                ↑       ↑                ↑
    ┏━━━━━━━━━━━┓┏━━━━━━━━━━━━━━━┓┏━━━━━━━━━━━┓┏━━━━━━━━━━━┓┏━━━━━━━━━━━━━┓
    ┃add_device ┃┃add_hwgenerator┃┃ add_input ┃┃ add_disk  ┃┃add_interrupt┃
    ┃_randomness┃┃  _randomness  ┃┃_randomness┃┃_randomness┃┃ _randomness ┃
    ┗━━━━━━━━━━━┛┗━━━━━━━━━━━━━━━┛┗━━━━━━━━━━━┛┗━━━━━━━━━━━┛┗━━━━━━━━━━━━━┛


#### Entropy sources

The APIs for the raw entropy sources of the LRNG include

* `add_device_randomness`: Device driver related data believed to provide entropy. The device driver specific value is mixed into the unseeded ChaCha20 DRNG and `input_pool` during boot along with the high-resolution time stamp, XORed with the Jiffies (Linux kernel timer). The value is requested only once, and it is not considered to contain enough entropy to award bits to the LRNGs entropy counter. **[[BSI p.52]](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/LinuxRNG/LinuxRNG_EN.pdf?__blob=publicationFile&v=16)**

* `add_hwgenerator_randomness`: HWRNGs supported by the Linux kernel, if available. The output of the HWRNG device is used to seed the ChaCha20 DRNG if needed, and then to seed the `input_pool` directly when the entropy estimator's value falls below the set threshold. (CPU HWRNG is not processed by the add_hwgenerator_randomness service function). **[BSI pp.52-54]**

* `add_input_randomness`: Key presses, mouse movements, mouse button presses etc. Repeated event values (e.g. key presses or same direction mouse movements) are ignored by the service function. **[BSI p.44]** 

    The event data consists of four LSBs of the event type, four MSBs of the event code, the event code itself, and the event value, all XORed together. **[BSI p.45]**
    
    The resulting event data is fed into the `input_pool` via `add_timer_randomness`, which prepends to the event value the 32 LSBs of a high-resolution timestamp, plus the 64-bit Jiffies timestamp. **[BSI p.55]**

    Each HID event contains 15.6 bits of Shannon entropy, but
      due to LRNG's conservative heuristic entropy estimation, on
      average only 1.29 bits of entropy is awarded to the event. **[BSI p.77]**

* `add_disk_randomness`: Hardware events of block devices, e.g.
      HDDs (but not e.g. SSDs). When a disk event occurs, the block
      device number as well as the timer state variable `disk->random`
      is mixed into the `input_pool` via `add_timer_randomness`.
       **[BSI pp.50-51]**

    Each disk event contains on average 17.7 bits of Shannon
      entropy, but only 0.21 bits of entropy is awarded to the
      event. **[BSI p.77]**

* `add_interrupt_randomness`: Interrupts (i.e. signals from SW/HW
      to processor that an event needs immediate attention) occur
      hundreds of thousands of times per second under average load. 
          The interrupt timestamps and event data are mixed into
      128-bit, per-CPU pool called `fast_pool`. When an interrupt
      occurs
      
     * The 32 LSBs of the high-resolution timestamp, the coarse Jiffies, and the interrupt number are XORed with the first 32-bit word of the `fast_pool`.

     * The 32 LSBs of the Jiffies and the 32 MSBs of the high-resolution timestamp are XORed with the second word of the `fast_pool`.

     * The 32 MSBs and LSBs of the 64-bit CPU instruction pointer value are XORed with the third and fourth word of the `fast_pool`. If no pointer is available, the XORed value is instead the return address of the `add_interrupt_randomness` function.

    The raw entropy mixed into the `fast_pool` is then distributed 
      more evenly with a function called `fast_mix`.

    The content of the `fast_pool` is mixed into the `input_pool` once it has data about at least 64 interrupt events, and (unless the ChaCha20 DRNG is being seeded) at least one second has passed since the `fast_pool` was last mixed in. The counter keeping track of the interrupt events is then zeroed. **[BSI pp.45-49]**
    
    Each interrupt is assumed to contain 1/32 bit of entropy. However, the measured Shannon entropy for each interrupt is 19.2 bits, which means each 128-bit `fast_pool` is fed 1228.8 bits of Shannon entropy. **[BSI p.77]**
    
    The entire content of the `fast_pool` is considered to increase the internal entropy of the `input_pool` by 1 bit. If the `RDSEED` (explained below) instruction is available, it is used to obtain a 64-bit value that is also mixed into the `input_pool`, and the internal entropy of the `input_pool` is
      considered to have increased by another bit. **[BSI p.48]**

Additional raw entropy sources include

* `RDSEED`/`RDRAND` CPU instructions:

    * **Intel**: A [pair of inverters](https://spectrum.ieee.org/computing/hardware/behind-intels-new-randomnumber-generator) feeds 512 bits of raw entropy to AES256-CBC-MAC based conditioner (as specified in NIST SP 800-38A), that can be requested bytes with the `RDSEED` instruction. The conditioner is used to create 256-bit seeds for the AES256-CTR based DRBG available via the `RDRAND` instruction. The DRBG is reseeded after every 511th sample of 128 bits (~8kB). [[p.12]](https://software.intel.com/sites/default/files/managed/98/4a/DRNG_Software_Implementation_Guide_2.1.pdf)

    * **AMD**: A set of 16 ring oscillator chains feeds 512 bits of raw entropy to AES256-CBC-MAC based conditioner again available via `RDSEED` instruction. The conditioner is used to produce 128-bit seeds -- a process that is repeated thrice to create a 384-bit seed for the AES256-CTR based DRBG available via the `RDRAND` instruction. The DRBG is reseeded at least every 2048 queries of 32-bits (8kB). [[pp.2-3]](https://www.amd.com/system/files/TechDocs/amd-random-number-generator.pdf)

    While the `RDSEED`/`RDRAND` instructions are used extensively, because the CPU HWRNG is not an auditable source, it is assumed to provide only a very small amount of entropy. **[BSI p.83]**

*  Data written to `/dev/(u)random` from the user space **[BSI p.38]**
          such as the 4096-bit `random-seed` that was obtained from the
          ChaCha20 DRNG and written on disk when the previous session
          ended and the system was powered off. **[BSI p.63]**
              While the random-seed [might not be mixed in early enough
          during boot to benefit the kernel](https://security.stackexchange.com/questions/183506/random-seed-not-propagating-to-the-entropy-pools-in-a-timely-manner), it is mixed into the `input_pool` before TFC starts.

* User space IOCTL of `RNDADDENTROPY`. **[BSI p.39]**


#### The input_pool

##### Overview

The `input_pool` is the 4096-bit primary entropy pool of the LRNG that compresses truly random events from different noise sources. **[[BSI p.19]](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/LinuxRNG/LinuxRNG_EN.pdf?__blob=publicationFile&v=16)** Together the noise sources and the `input_pool` form a constantly seeded, non-deterministic random number generator (NDRNG), that seeds the ChaCha20-based deterministic random number generator (DRNG). **[BSI p.20]**

##### Initialization of the input_pool

The `input_pool` is initialized during boot time of the kernel by mixing following data into the entropy pool:

1. The current time with nanosecond precision (64-bit CPUs).
2. Entropy obtained from CPU HWRNG via `RDRAND` instruction, if available.
3. System specific information such as OS name, release, version, and a HW identifier. **[BSI pp.30-31]**

##### Initial seeding and seeding levels of the input_pool

After a hardware event has occurred, the entropy of the event value is estimated, and both values are mixed into the `input_pool` using a function based on a linear feedback shift register (LFSR), one byte at a time. **[BSI p.23]**

The `input_pool` only keeps track if at one point it has had 128 bits of entropy in it. When that limit is exceeded, the variable `initialized` is set to one. **[BSI p.22]** This level of entropy is reached at early boot phase (by the time the user space boots). [[**LRNG p.6**]](http://www.chronox.de/lrng/doc/lrng.pdf)

Once the `input_pool` is initialized, the ChaCha20 DRNG is reseeded from the input_pool [**[random.c L791]**](https://github.com/torvalds/linux/blob/master/drivers/char/random.c#L791) using 128..256 bits of entropy **[BSI pp.27-28]** from the `input_pool` and at that point the DRNG is considered fully seeded [**[random.c L1032]**](https://github.com/torvalds/linux/blob/master/drivers/char/random.c#L1032).

##### State transition and output of the input_pool

When outputting entropy from the `input_pool` to the ChaCha20 DRNG, the `input_pool` output function first compresses the entire content of the `input_pool` with SHA-1 like hash function that has the transformation function of SHA-1, but that replaces the constants of SHA-1 with random values obtained from CPU HWRNG via RDRAND, if available. **[BSI p.29]**

The output function also "folds" the 160-bit digest by slicing it into two 80-bit chunks and by then XORing them together to produce the final output. At the same time, the output function reduces the `input_pool` entropy estimator by 80 bits. **[BSI p.18]**
 
The "SHA-1" digest is mixed back into the `input_pool` using the LFSR-based state transition function to provide backtracking resistance. **[BSI p.18]**

If more than 80-bits of entropy is requested, the hash-fold-yield-mix-back operation is repeated until the requested number of bytes are generated. (Reseeding the ChaCha20 DRNG requires four consecutive requests.) **[BSI p.18]**

##### Reseeding of the input_pool

The `input_pool` is reseeded constantly as random events occur. The events are mixed with the LFSR, one byte at a time. When the `input_pool` is full, more entropy keeps getting mixed in which is helpful in case the entropy estimator is optimistic: At some point the entropy will have reached the maximum of 4096 bits. When the `input_pool` entropy estimator considers the pool to have 4096 bits of entropy, it will output 1024 bits to `blocking_pool` for the use of `/dev/random`, and it will then reduce the `input_pool`'s entropy estimator by 1024 bits. **[BSI pp.59-60]**


#### The The ChaCha20 DRNG

##### Overview

The LRNG uses the ChaCha20 stream cipher as its primary DRNG.

According to 
**[[BSI p.32]](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/LinuxRNG/LinuxRNG_EN.pdf?__blob=publicationFile&v=16)**, 
the internal 64-byte state of the DRNG consists of

* 16-byte constant `b'Expand 32-byte k'` set by the designer (djb) 
* 32-byte key (the only part that is reseeded with entropy)
* 4-byte counter (the counter is [actually 64-bits](https://lkml.org/lkml/2019/5/30/867))
* 12-byte nonce 

In addition, the DRNG state contains a 4-byte timestamp called `init_time`, that keeps track of when the DRNG was last seeded. **[BSI pp.32-33]**

##### Initialization of the DRNG

The ChaCha20 DRNG is initialized during the boot time of the kernel by using the content of the `input_pool` (considered to have poor entropy at this point **[BSI p.32]**) for key, counter, and nonce parts of the DRNG state.

Each of the three values is XORed with the output from CPU HWRNG obtained via `RDSEED` or `RDRAND` instruction (if available -- otherwise only the key is XORed, and that's done with a timestamp obtained via the `RDTSCP` instruction). **[BSI pp.32-33]**

The initialization is completed by setting the `init_time` to a value that causes the ChaCha20 DRNG to reseed from the `input_pool` the next time it's called.
**[BSI p.33]**
**[random.c
[L810](https://github.com/torvalds/linux/blob/master/drivers/char/random.c#L810),
[L976](https://github.com/torvalds/linux/blob/master/drivers/char/random.c#L976)
]**

##### Initial seeding and seeding levels of the DRNG

If the `RDSEED` or `RDRAND` is available during initialization, and if the CPU HWRNG is trusted by the kernel, the DRNG is seeded by the CPU HWRNG, after which it is considered fully seeded and the seeding steps below are skipped. The DRNG will still reseed from the `input_pool` the next time it is called. **[BSI p.35]**

**Initially seeded state**

During initialization time of the kernel, the kernel injects four sets of data from the `fast_pool` into the DRNG (instead of the `input_pool`). Each set contains event data and timestamps of 64 interrupt events from `add_interrupt_randomness`. **[BSI p.35]** In addition, all content from the `add_device_randomness` source is mixed into the DRNG key state using an LFSR with a period of 255. **[BSI p.52]** Once the entropy sources have been mixed in, the DRNG is considered to be initially seeded. **[BSI p.35]**

**Fully seeded state**

As of Linux kernel 4.17, if the CPU HWRNG is not trusted, the DRNG is considered fully seeded (256-bit entropy) only after, during initialization time of the kernel, the `input_pool` has reached 128-bit entropy, and the DRNG is reseeded by XORing 128..256 bits from the `input_pool` with the key part of the DRNG state. **[BSI p.138]** The time to reach this state might take up to 90 seconds **[BSI p.70]**, but as the installation of TFC via Tor takes longer than that, the DRNG is most likely fully seeded by the time TFC generates keys and no blocking affects the user experience. According to **[BSI p.39]** and **[LRNG p.11]**, the ChaCha20 DRNG blocks until it is fully seeded. This means TFC's key generation also blocks until the ChaCha20 DRNG is fully seeded.

##### State transition and output of the DRNG

When outputting from ChaCha20 DRNG to the caller, the ChaCha20 block function is invoked repeatedly until the requested number of bytes are generated. Each invoke yields a 64-byte output block that is essentially part of the keystream that in the context of stream cipher would be XORed with the plaintext to produce the ciphertext. With each generated block the internal 32-bit counter value of the ChaCha20 state is incremented by one to ensure unique blocks.
 **[BSI p.33]**,
[**[chacha.c L89]**](https://github.com/torvalds/linux/blob/master/lib/crypto/chacha.c#L89#L89),
[**[random.c L1064]**](https://github.com/torvalds/linux/blob/master/drivers/char/random.c#L1064)

The state of the DRNG is further stirred by XORing the second 32-bit word of the nonce with the output from `RDRAND` instruction, if available. **[BSI p.33]**

Once the amount of requested random data has been generated, the state update function is invoked, which takes a 256-bit block of unused keystream and XORs it with the key part of the ChaCha20 state to ensure backtracking resistance. **[BSI pp.33-34]**

According to **[BSI pp.39-40]**, the random bytes used in TFC are obtained with the `getrandom()` syscall instead of the `/dev/urandom` device file. This has two major benefits:

1. It bypasses the Linux kernel's virtual file system (VFS) layer, which reduces complexity and possibility of bugs, and

2. unlike `/dev/urandom`, `getrandom()` blocks until it has been fully seeded.

##### Reseeding of the DRNG

The ChaCha20 DRNG is reseeded automatically every 300 seconds irrespective of the amount of data requested from the DRNG **[BSI p.32]**. The DRNG is reseeded by obtaining 128..256 bits of entropy from the `input_pool`. In the order of preference, the entropy from the `input_pool` is XORed with the output of

1. 32-byte value obtained via the `RDSEED` CPU instruction, or
2. 32-byte value obtained via the `RDRAND` CPU instruction, or
3. eight 4-byte high-resolution time stamps

The result is then XORed with the key component of the DRNG state **[BSI p.34]**.


#### getrandom() and Python

Since Python 3.6.0, `os.urandom` has been a wrapper for the best 
available CSPRNG. The 3.17 and earlier versions of the Linux kernel
do not support the `getrandom()` call, and Python 3.7's `os.urandom`
will in those cases fall back to non-blocking `/dev/urandom` that is
not secure on live distros as they have low entropy at the start of
the session.
    To avoid possibly unsafe key generation, instead of `os.urandom`
TFC uses the `os.getrandom(size, flags=0)` explicitly. This forces
use of recent enough Python interpreter (3.6.0 or later) and limits
the Linux kernel version to 3.17 or newer. To make use of the LRNG,
the kernel version required by TFC is bumped to 4.8, and to make
sure the ChaCha20 DRNG is always seeded from `input_pool` before its
considered fully seeded, the final minimum requirement is 4.17).
    The flag 0 [means](https://manpages.debian.org/testing/manpages-dev/getrandom.2.en.html) `getrandom()` will block if the DRNG is not fully 
seeded.

Quoting [PEP 524](https://www.python.org/dev/peps/pep-0524/):

> The os.getrandom() is a thin wrapper on the getrandom() syscall/C function and so inherit of its behaviour. For example, on Linux, it can return less bytes than requested if the syscall is interrupted by a signal."

However, quoting [LWN](https://lwn.net/Articles/606141/) on `getrandom()`:

> --reads of 256 bytes or less from /dev/urandom are guaranteed to return the full request once that device has been initialized.

Since the largest key generated in TFC is the 56-byte X448 private
key, `getrandom()` is guaranteed to always return enough bytes. As a
good practice however, TFC checks that the length of the obtained
entropy is correct.

#### BLAKE2 compression

The output of `getrandom()` is further compressed with BLAKE2b. The preimage resistance of the hash function protects the internal state of the entropy pool just in case some user decides to modify the source to accept pre-4.8 Linux kernel that has no backtracking resistance. Another reason for the hashing is its [recommended by djb](https://media.ccc.de/v/32c3-7210-pqchacks#video&t=1116).

Since BLAKE2b only produces [1..64 byte digests](https://blake2.net/), its use limits the size of the generated keys to 64 bytes. This is not a problem for TFC because again, the largest key it generates is the 56-byte X448 private key.
</details>

### Forward secrecy

Forward secrecy is the process of using ephemeral keys to prevent retrospective decryption of intercepted ciphertexts with keys that are compromised from the endpoint at some point. TFC provides per-packet forward secrecy with what's called a hash ratchet. 

In hash ratchet, the message key (denoted with **K<sub>M</sub>**) is passed through a key derivation function (KDF) after every encryption or decryption operation. The pre-image resistance of the hash function used in the KDF prevents deriving previous key(s) from the current key. Since hash function maintains the entropy of the initial key, no salt or slow hash functions are necessary for the KDF. The KDF used in TFC is the BLAKE2b hash function.

In the situation where one or more packets have dropped, the encryption key determined by the hash ratchet state of the Transmitter Program will have advanced further, than what the decryption key of the Receiver Program's hash ratchet state would expect. To determine the unknown offset, the Receiver Program needs to know how many times the Transmitter Program had at that point passed the initial message key through the KDF. This information is delivered using a value called the hash ratchet counter (harac for short). 

The harac is a 64-bit zero-padded bit string. The counter space might sound small, but even at a fictitious rate of 5 billion packets per second, it would last for more than 100 years.

The harac is delivered next to the forward secret assembly packet. It is encrypted with a static key called the header key (denoted with **K<sub>H</sub>**). The header key is generated independently, or it is domain-separated from the X448 shared key using the KDF. Static nature of the header key is not a problem as the nonce space is massive (192 bits). The primary function of harac encryption is to provide authenticity with the Poly1305 MAC, as maliciously altered harac value would DoS the Receiver Program as it would try to catch up with a purported ratchet state that claims to be, e.g., hundred million derivations ahead of the Receiver Program's ratchet state. The secondary function is to provide confidentiality to the number of sent packets the value reveals.

The harac also has a secondary purpose: it serves as a deterministic, never repeating counter that is mixed together with the previous key when hashing. This ensures that the keys will never fall into a short cycle. 

When the Receiver Program receives a packet, it will first decrypt the harac using the header key. If the decrypted harac indicates packets have dropped, Receiver Program will display a notification about the missed packets. It will then catch up with the purported ratchet state. If decryption of the assembly packet with the derived message key is successful, Receiver Program will store the next unused message key and harac value to the key database.

One thing to consider is, frenemies (malicious contacts) are always able to perform the DoS attack (described above) against user's Receiver Program. Receiver Program will prompt the user to verify whether or not they would like to catch up with the ratchet state, but preventing the attack is a hard problem because the contact could send multiple packets that are just below the set warning threshold (100,000 missed packets). Such attacks can, however, be detected by multiple notifications of Receiver Program, and it should be dealt by removing the contact from TFC.

TFC does not use Signal-style double-ratchet (hash-ratchet + Diffie-Hellman ratchet) because it would require the user to manually type a new public key from Receiver Program to Transmitter Program after every received message; Such a protocol would be unusable. TFC does, however, allow users to switch to new keys by re-adding the contact and re-exchanging keys. This procedure does not mix in entropy from the previous ratchet, as due to the risk of dropped packets, user and contact might end up in inconsistent state by deriving different keys. This would create a lot of hassle, from which TFC could not recover without creating completely new keys.


### Endpoint security vs future secrecy

Due to lack of Diffie-Hellman ratchet, TFC is unable to provide a property called future secrecy. What it means is, if TFC's private keys are compromised at any point, the adversary can decrypt all messages until the users exchange new keys. While Signal avoids this problem by continually mixing in new entropy, the effectiveness of future secrecy can be questioned: If private keys of Signal are stolen at any point, it is highly likely that the endpoint is infected with malware that can exfiltrate all future keys and plaintexts to the adversary.

Future secrecy is effective in cases where the adversary compromises only a limited set of keys, if decryption attack with keys is only passive, or if MITM attack that leverages the keys seizes at some point. It should be emphasized that weak endpoint security of networked TCBs is not the fault of messaging tools. Future secrecy is by no means a bad thing and having it on applications that run on networked TCB is excellent. TFC is unable to provide it, but in turn, it can provide what networked TCBs cannot -- security against remote data exfiltration.


##### Mixing of key entropy vs. initial key security

The future secrecy property in Signal also avoids the issue of using weak keys for extended periods, because new entropy is continuously mixed into kernel CSPRNG and from there into DH key pairs. TFC is unable to mix in new entropy and is thus dependent on the security of the initial key. All keys are generated using getrandom() syscall that on modern Linux kernels (3.17 and newer) blocks when the internal state of the CSPRNG has less than 256 bits of entropy. Generated keys can, therefore, be assumed to be secure even if the Transmitter Program is run on a live distro. Instead of mandating minimum kernel version of 3.17, TFC expects 4.17 or later; This ensures not just that getrandom() syscall is available, but that the kernel also utilizes the newer ChaCha20-based CSPRNG (a.k.a LRNG).

### Deniable authentication

Since ciphertexts are signed with symmetric Poly1305 MACs (as opposed to digital signatures in, e.g., PGP and iMessage), messages in TFC do not include cryptographic proofs about message's authorship. The conversing parties -- Alice and Bob -- are both in possession of the symmetric keys they use to sign and verify messages they send each other. The shared key means Alice can be sure Bob was the sender of the message (because she knows it was not her), but also, that Alice cannot show the message to a third party and prove Bob wrote it because Alice could also have created the message and the MAC.


##### On MAC publishing

[OTR-protocol](https://otr.cypherpunks.ca/Protocol-v3-4.1.1.html) has an interesting feature: it publishes expired MAC keys after the session ends. The publishing allows any third party to forge conversations afterwards. TFC is unable to do this because hash ratchets are deterministic; Even if the Poly1305 MAC keys were domain separated from the hash ratchet's message keys, Receiver Program of Alice could not notify Transmitter Program of Bob which messages it has received. Because in TFC the session lasts until the users perform the next key exchange, the only way to publish MAC keys would be at some point in a trailing message.

Were MITM attacker Mallory to prevent the flow of messages to Alice, a trailing message from Bob would contain the MAC key of the first message. As stream ciphers are malleable, this would allow Mallory to create an undetectable existential forgery in cases where she knows the plaintext content of the first message for whatever reason (e.g., high priori probability).


### No snake oil promises about sender based control

Sender-based control is an unreliable security feature that is advertised as a way to protect the sender from the recipient, by removing messages delivered to the said recipient. This feature is mostly snake oil because it requires the software to be proprietary and to limit the rights of the recipient. TFC is free and open source software (FOSS) for a very good reason: It is much harder for nation states to coerce backdoors into FOSS tools. Because TFC is FOSS, it means any user can trivially edit their Receiver Program not to remove the messages asked by the sender (this would probably require commenting out 1..3 lines of code). Secondly, even if TFC was proprietary software, no magical crypto dust makes the recipient unable to take a screenshot, or use an external camera to record incoming messages.

TFC does, however, provide sender based control over **partially** transmitted data. What this means is, messages longer than 254 bytes (when compressed) are sent over multiple assembly packets. The content is encrypted with an inner layer of XChaCha20-Poly1305, the key of which is concatenated to the ciphertext. As long as the packet delivery is canceled before the 1..2 last assembly packets that contain the inner key are delivered to sender's Relay Program the recipient is unable to decrypt the long transmission. Unfortunately, the inner layer of encryption makes partial transmissions impossible in cases where for example, a dissident must quickly upload as much of the data as possible before their door gets busted down. Such situations are however likely to be much rarer than those where the user realizes they have been sending a large message or file to a wrong contact.

TFC's command `/whisper` allows the user to send a message to the recipient and request it not to be logged. The request is accepted as long as the recipient does not change the behavior of their Receiver Program. It is meant to be used by conversing parties as a mean to choose what messages are logged, and what to keep off-the-record. Providing the feature might appear hypocritical, but at no point is the feature advertised as means to protect the user from the recipient, it only protects the user and the recipient from third parties in cases where the recipient has not disabled the feature from the source code.


## Master key derivation and data at rest

During the initial launch, Transmitter and Receiver Programs first generate a 256-bit salt, and then prompt the user to enter and confirm a master password, that is fed together with the salt into the password based key derivation function Argon2id to derive the 256-bit master key, that will be used to encrypt data at rest.

As the key derivation time is limited by user's tolerance to wait, TFC optimizes security by scaling threads to match the CPU, and by tweaking the `time_cost` and `memory_cost` according to [best practices](https://argon2-cffi.readthedocs.io/en/stable/parameters.html), until key derivation takes between three and four seconds. The three second minimum is the recommendation for *key derivation for hard-drive encryption* defined in the [Argon2 RFC draft](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-4).

The implementation first uses as much memory as possible. It then increases `time_cost` until the key derivation takes between three and four seconds. Once `time_cost` that exceeds three second limit has been determined, if key derivation then takes over four seconds (value we consider too long for decent user experience), `memory_cost` is tweaked by doing a binary search for a value that leads to key derivation time between three and four seconds. 

While this configuration is as good as password based key derivation gets, it is a truism no KDF configuration is strong enough if the user has chosen a weak password (i.e. a short one or one that's in the attacker's password dictionary).

The 32-byte BLAKE2b digest of the master key is stored together with `salt`, `time_cost`, `memory_cost` and `parallelism` parameters into database `{tx,rx}_login_data`. The master key will be derived from the password (entered into TFC's login screen) and salt every time Transmitter and Receiver Programs are launched, and it is only accepted if its hash matches the one in the database. Forgetting the password or tampering/deleting the login data file renders all user-data inaccessible. Under the assumption password remains unbreakable by the adversary, encrypted databases help against following threats:

<details>
  <summary><b>Wear leveling</b></summary>

All data is encrypted before it touches the hard drive: These are increasingly becoming SSDs that don't overwrite data the way magnetic drives do.
</details>

<details>
  <summary><b>Physical data exfiltration</b></summary>

In the case where the adversary has not remotely exploited Destination Computer with a keylogger that copies TFC master password, physical access where encrypted data is merely exfiltrated means attacker is unable to access sensitive data. Similar protection can also be obtained with Full Disk Encryption (FDE) and by ensuring the encrypted disk is not mounted during off-hours. TFC keeps data secure even when FDE drive is mounted, but TFC is not running. 
</details>

<details>
  <summary><b>Physical data tampering</b></summary>

Since databases use authenticated encryption (XChaCha20-Poly1305), any tampering of TFC databases results in MAC error when the user enters the correct password. If however the hash, salt, or key derivation parameters in login data have been tampered with, the user only gets a warning that the entered password was incorrect.
</details>

<details>
  <summary><b>Impersonation</b></summary>

In situations where the Source Computer or the Destination Computer is left powered on (something the user should never do), but TFC master password has not been entered, encryption of data prevents communication to contacts while impersonating as the user.
</details>

<details>
  <summary><b>Database metadata leak</b></summary>

TFC databases are padded so that regardless of content, as long as the user has 50 or fewer contacts, that form 50 or fewer groups, each with 50 or fewer members, databases do not leak any metadata about the user's TFC configuration. The user can increase contact and group database limits from settings with `/set` command (values need to be multiples of 10), which will cause the application to expand the padded database size. Different types of data in databases are stored in constant length format:

* Logged assembly packets are stored as 256-byte strings

* UNIX timestamps for logged messages are stored as 4-byte strings

* Unicode string variables like group names and nicks are stored as PKCS #7 padded, UTF-32 encoded strings (length of 1024 bytes)

* Integers are stored as (big-endian) unsigned long long (length of 8 bytes)

* Floats are stored as binary64 (length of 8 bytes)

* Booleans are stored as single bytes (`\x00` or `\x01`)

* Symmetric keys, public key fingerprints, and TFC accounts (=Tor Onion service Ed25519 public keys) are stored as 32-byte strings.

Based on the padding formats above

* Contact and key databases will be padded with dummy contacts with dummy data (until not necessary, i.e. when the database has 50 contacts and is full).

* Groups in group database will be padded with dummy members (until not necessary)

* Group database will be padded with dummy groups with dummy members (until not necessary)

Unfortunately, the message log database cannot be effectively padded, so it leaks metadata about the total number of sent and received messages. Because of this, logging of messages is disabled by default. If the setting `logfile_masking` is enabled, Transmitter and Receiver Program of the user will during traffic masking (explained later) log each output assembly packet to prevent an attacker who correlates what Source Computer outputs with the logfile size, from deducing how large portion of the packets were, e.g., whispered messages.
</details>

## Secure communication between Source and Destination Computer

Messaging applications have practically always consisted of two parts: the input box and the conversation window. In TFC, the Transmitter Program is essentially the input box (with visible input history and key/contact management interfaces), and the Receiver Program is the conversation window. To decrypt messages from Bob, the Receiver Program of Alice must have a copy of the symmetric encryption key used by the Transmitter Program of Bob. To make conversation easy to follow on one screen, messages sent by Bob must also be displayed by his Receiver Program. This means Bob's Receiver Program must also have a copy of the symmetric key. As the Receiver Program is not trusted to generate keys for communication purposes, a way to deliver them from his Source Computer is needed. Additionally, Transmitter and Receiver Programs need to have a synchronized state (e.g., settings and active conversation window). To maintain that, instead of entering commands into two computers every time, the Receiver Program should be managed via the Transmitter Program to the furthest extent with commands. But how should the commands and symmetric message keys be delivered from the Source Computer to the Destination Computer?

Removable media is slow, introduces a running cost and risks data remanence that endangers forward secrecy. Separate direct data diode enforced channel from Source to Destination Computer is problematic as serial name (e.g. `/dev/ttyUSB0`) mapping is not persistent. Even with UIDs and dedicated interfaces, users could still misconfigure data diode wiring: Source Computer might, therefore, output sensitive data intended for Destination Computer to Networked Computer. In such case infected Networked Computer and Destination Computer might fool the user into thinking data was correctly sent: Source Computer cannot tell to what device it is outputting data. Destination Computer, on the other hand, might accept volatile commands from the Networked Computer (that appear to come from the Source Computer over the trusted channel), and for example remove log files or worse, PSKs that might have been exchanged over meetings that required expensive travel.

Commands and message keys need to be encrypted before delivery, and in such case, users might as well route them via the Networked Computer: This simplifies the hardware layout significantly and reduces cost. The symmetric encryption key for this purpose is called the `local key`, and it needs to be delivered from Source Computer to Destination Computer somehow. The key should definitely not be derived from a password, because [users choose on average 40-bit passwords](https://www.microsoft.com/en-us/research/publication/a-large-scale-study-of-web-password-habits/) and brute forcing such key space would be trivial. As stated above, public key cryptography is a bad idea as Destination Computer might have been compromised with a magic packet received via the Networked Computer. Were the computer use a key pair determined by Mallory, she could undetectably derive the shared key by combining the known Receiver Program's private key with the Transmitter Program's public key (as it transits through the Networked Computer). Delivering the key via removable media or trusted serial interface has the same problems as in the cases described above regarding message key or command delivery.

The following image describes how the local key is delivered from the Source Computer to the Destination Computer.

![](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/9_local_key2.png)
[Local key delivery protocol](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/9_local_key2.png)

1. The Transmitter Program generates three 256-bit symmetric keys: local key **K<sub>L</sub>**, local header key **K<sub>LH</sub>**, and local key encryption key **K<sub>KE</sub>**. It also generates a one byte long confirmation code **cc**.

2. The Transmitter Program encrypts **K<sub>L</sub>**, **K<sub>LH</sub>** and **cc** using **K<sub>KE</sub>** (**||** denotes concatenation).

3. The Transmitter Program outputs the ciphertext **CT** to the Destination Computer via the Networked Computer.

4. The Transmitter Program displays **K<sub>KE</sub>** on Source Computer screen. The format is the same as Bitcoin's WIF: Base58 with integrated 4-byte checksum, sliced into even length chunks to help with typing.

5. The user enters **K<sub>KE</sub>** on the Receiver Program using the Destination Computer's keyboard.

6. The Receiver Program decrypts **CT** using **K<sub>KE</sub>**.

7. If decryption was successful, the Receiver Program stores **K<sub>L</sub>** and **K<sub>LH</sub>** to key database and reveals **cc** to the user.

8. The user types **cc** to Transmitter Program to verify **K<sub>L</sub>** and **K<sub>LH</sub>** have been delivered to Receiver Program. 

    If **cc** was correct, Transmitter Program stores **K<sub>L</sub>** and **K<sub>LH</sub>** to key database and allows the user to add the first contact. 

After a contact has been added, a new local key can be created with Transmitter Program's command `/localkey`.


#### Confirmation codes

Confirmation codes are used in TFC to ensure important data like keys were successfully delivered, before the program allows the user to continue. The confirmation code is designed to be as short as possible to type, but complex enough (256 choices), so the user does not attempt to brute force it. If due to a loose connection or transmission error data (like the **CT** above) was not delivered to Destination Computer, the packet can be resent by simply pressing <kbd>Enter</kbd>.


## Adding contact

### Contact discovery and communication between Networked Computers

Before user's TFC setup can exchange encrypted messages, files or public keys (**TFC DATA** in the image below), it needs to connect to the recipient. 

![](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/10_networked_computers3.png)
[TFC connection establishment over V3 Onion Services](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/10_networked_computers3.png)

**NOTE**: In the explanation below, a single quote `'` is used to denote data from the contact.

**NOTE**: Although local key delivery was explained in the previous chapter, some of the following steps take place automatically in the background even before the local key delivery.

1. The Relay Program generates an ephemeral X448 private key **K<sub>S</sub>** for the session and derives a public key **K<sub>P</sub>** from that.

2. The Transmitter Program generates a long-term ed25519 private key **K<sub>OS</sub>** for the Onion Service, and a confirmation code **cc**, and sends them to the Relay Program.
 
3. The Relay Program uses **K<sub>OS</sub>** to set up a v3 Tor Onion Service (aka Tor Hidden Service).

4. The Relay Program displays the confirmation code **cc** to the user.

5. The user types the **cc** to their Transmitter Program so the program knows the Onion Service private key was successfully delivered and that local key delivery can begin.

    **NOTE: The local key setup takes place at this point during the first run.**

6. Transmitter and Relay Program display the user's TFC account (derived from **K<sub>OS</sub>**) to them.

7. Alice and Bob obtain each other's TFC account over an [authenticated channel](https://en.wikipedia.org/wiki/Secure_channel).

8. Alice and Bob type each other's TFC account, nick and preferred key exchange method into their Transmitter Program.

9. The Transmitter Program stores the contact's TFC-account and forwards it to the user's Relay Program on Networked Computer. (Transmitter Program will deliver the Onion addresses of existing contacts to the Relay Program along with the Onion Service ed25519 private key every time it starts).

10. The TFC account is the v3 Onion Service URL without `http://` and `.onion`. (Note that despite the protocol claiming to be HTTP, all connections to `.onion` servers are encrypted using TLS (HTTPS)-equivalent encryption.) For example

    * Let TFC account of Bob be `bobpkjrwo7i3xtryurt4ab4nmo376as7axju5lzimmecrehhzlga56qd` and
    * Let TFC account of Alice be `alicew6wvfxqjqknntxrt6rw3ngwt6hqeqrcgldu47miq2xfzfqhqsid`

    When Relay Program of Bob receives Alice's TFC account, it connects to Alice via URL `http://alicew6wvfxqjqknntxrt6rw3ngwt6hqeqrcgldu47miq2xfzfqhqsid.onion`

    To ensure contacts can request **TFC DATA** intended only for them, the Relay Program's server requires the requester to provide a URL token known only by the two participants. The URL token is agreed using X448:

    The Relay Program's server publishes **K<sub>P</sub>** under the root domain:
    
    * `http://alicew6wvfxqjqknntxrt6rw3ngwt6hqeqrcgldu47miq2xfzfqhqsid.onion` for Alice
    * `http://bobpkjrwo7i3xtryurt4ab4nmo376as7axju5lzimmecrehhzlga56qd.onion` for Bob 

    Since the Onion address authenticates the Tor Onion Service, **K<sub>P</sub>** obtained from the server can be assumed to be authentic.

11. Once the public key of the contact's Relay Program is obtained, the user's Relay Program combines its private key with the contact's public key to derive the X448 shared key **SSK**: 

    **SSK** = BLAKE2b(X448(**K<sub>S</sub>**, **K<sub>P'</sub>**)) = BLAKE2b(X448(**K<sub>S'</sub>**, **K<sub>P</sub>**))

12. The Relay Program of Bob uses **SSK** as the URL token to request **TFC DATA** from Alice with GET method to URLs 

* `http://alicew6wvfxqjqknntxrt6rw3ngwt6hqeqrcgldu47miq2xfzfqhqsid.onion/`**SSK**`/messages`
* `http://alicew6wvfxqjqknntxrt6rw3ngwt6hqeqrcgldu47miq2xfzfqhqsid.onion/`**SSK**`/files`

and Alice respectively does the same by using URLs 

* `http://bobpkjrwo7i3xtryurt4ab4nmo376as7axju5lzimmecrehhzlga56qd.onion/`**SSK**`/messages`
* `http://bobpkjrwo7i3xtryurt4ab4nmo376as7axju5lzimmecrehhzlga56qd.onion/`**SSK**`/files`

The path can be observed e.g. with Tor Browser. The upper window shows the URL token related X448 public key in hexadecimal format, and in the lower one, entering the correct URL token allows requesting the ciphertext.  

![](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/11_ssk_example.png)
[Data exchanged by Relay Programs is available by knowing the Onion URL and URL token](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/11_ssk_example.png)


Security is provided by the following properties:

* The address of the Onion Service that belongs to Bob is pinned to Alice's Transmitter and Relay Programs: Malicious contact Chuck is, therefore, unable to change the URL Alice's Relay Program connects to, so they are unable to change the URL token public key **K<sub>P</sub>**.
* The private key **K<sub>OS</sub>** never leaves the Networked Computer, and deriving the private key from the Onion address is as hard as [ECDLP](https://en.wikipedia.org/wiki/Discrete_logarithm#Cryptography) for Curve25519. Chuck is, therefore, unable to create an Onion Service with an identical Onion-address.
* Upon connection, the purported path is validated in constant time to prevent side-channel attacks from leaking the **SSK**. Chuck is, therefore, unable to obtain the path to request packets it is not authorized to receive. Deriving the SSK from the public key is as hard as ECDLP for Curve448.

The key exchange used to derive URL token is not authenticated via any means other than by the v3 Onion address in the TFC account. The reason for this is Mallory who has compromised the Networked Computer has access to private keys related to the Onion Service in any case. However, while in such situation the outer layer of encryption and possibly the anonymity Tor provides is lost, the situation is similar to that when the outer layer of Signal's encryption (TLS) is broken: There still exists an inner layer of end-to-end encryption that protects the content. The key exchanges related to the inner layer are explained right after the next chapter.


#### Contact requests

One aspect not mentioned above is only one party needs to obtain the authentic TFC account of another user. When the Relay Program attempts to connect to an Onion Service, if no key exchange has yet been performed, the Onion Service will be reported by the Transmitter Program to be a pending contact. For each pending contact, the Relay Program will first keep sending a contact request by connecting to 

    http://bobpkjrwo7i3xtryurt4ab4nmo376as7axju5lzimmecrehhzlga56qd.onion/contact_request/alicew6wvfxqjqknntxrt6rw3ngwt6hqeqrcgldu47miq2xfzfqhqsid

until the Onion Service acknowledges it has received the contact request. The Relay Program of the user will then load the public key used in URL token derivation, and wait if the requested contact accepts the contact request by connecting to the user's Onion Service, deriving the SSK, and offering the TFC data (Transmitter Program's X448 public key or first PSK-message) via the `<address>.onion/<SSK>/messages` path. Until then, there is no way for the initializer to know if the other party has accepted the contact request.
 
##### Abuse potential

While TFC by default only shows each contact request once per session, there is no computational overhead* to generate valid Onion Addresses. The abuse potential of the anonymous contact request is an unfortunate side effect: Since contact requests can't require authentication, attackers can anonymously spam random contact requests to a known Onion URL. It is therefore recommended the user keeps their TFC account secret. This also prevents unauthorized users from knowing when the user's TFC is running. 

The attack is not expected to be a major issue as it is based on the fact it's noisy, and it would alert the user someone has ill intentions towards them. If the spam would turn out to be a problem, contact requests can optionally be turned off with the command `/set accept_contact_requests False`. Disabling the contact requests is not visible to the attacker in any way: the server will still report it has acknowledged the contact request. Disabling the contact requests also does not block adding contacts completely, as the built-in mechanism isn't the only way to exchange Onion Addresses.

*One possibility to deal with this issue would be to only display vanity Onion Addresses that have their first `n` characters fixed to some value. For example, by accepting only requests from unique Onion Service accounts that start with e.g. `tfc`, it would force the attacker to generate on average 32,768 keys for every spam request. Setting such limits can however hurt the users on slower hardware, and in some situations such as e.g. having hard copies of TFC accounts would reveal the purpose of the Onion addresses to a third party who finds the list. 


### X448

The X448 key exchange is described in the following image:

![](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/12_x448.png)
[X448 key exchange](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/12_x448.png)

**NOTE**: In the explanation below, a single quote `'` is used to denote data from the contact.

1. The Transmitter Program generates an X448 private key **K<sub>S</sub>** and derives a public key **K<sub>P</sub>** from that.

2. The public key **K<sub>P</sub>** is sent to the contact as **TFC DATA** via the Tor Onion Service (explained above).

3. The Relay Program of the user displays the contact's public key **K<sub>P'</sub>** once the Relay Programs have connected to each other.

4. The user manually types the contact's public key **K<sub>P'</sub>** to their Transmitter Program. Bitcoin's Wallet Import Format is again used here. However, whereas the local key decryption key uses the Mainnet header, X448 public keys use the Testnet headers. This way the user is unable to accidentally enter the wrong type of key to the wrong field.

5. The Transmitter Program derives the X448 shared secret from the private key **K<sub>S</sub>** of user and the public key **K<sub>P'</sub>** of contact. Because the raw bits of the X448 shared secret might not be uniformly distributed in the keyspace (i.e. bits might have bias towards 0 or 1), Transmitter Program passes the raw shared secret through a computational extractor (BLAKE2b CSPRF in this case) to ensure uniformly random shared key. The Transmitter Program uses this shared key as a source key, and feeds it together with a public key (counter) and the type of the key (context variable), into a KDF (BLAKE2b) to derive unidirectional message and header subkeys and fingerprints:

        sender_message_key   = blake2b(message=receiver_public_key, key=x448_shared_key, person=b'message_key')
        receiver_message_key = blake2b(message=sender_public_key,   key=x448_shared_key, person=b'message_key')
        sender_header_key    = blake2b(message=receiver_public_key, key=x448_shared_key, person=b'header_key')
        receiver_header_key  = blake2b(message=sender_public_key,   key=x448_shared_key, person=b'header_key')
        sender_fingerprint   = blake2b(message=sender_public_key,   key=x448_shared_key, person=b'fingerprint')
        receiver_fingerprint = blake2b(message=receiver_public_key, key=x448_shared_key, person=b'fingerprint')

6. The Transmitter Program prompts the user to establish an end-to-end encrypted call with [Signal](https://signal.org/) by Open Whisper Systems and to verify the TFC public key fingerprints **F** and **F'**. 

7. The Transmitter Program encrypts contact's TFC account, nick, message keys **K<sub>M</sub>** and **K<sub>M'</sub>**, and header keys **K<sub>H</sub>** and **K<sub>H'</sub>** with the local key **K<sub>L</sub>**.

8. The Transmitter Program outputs the ciphertext **CT** to the Receiver Program via the Networked Computer.

9. The Receiver Program decrypts the ciphertext using **K<sub>L</sub>** and stores the contact's TFC account, nick, **K<sub>M</sub>**, **K<sub>M'</sub>**, **K<sub>H</sub>** and **K<sub>H'</sub>** to its key and contact databases.

10. The Receiver Program displays a confirmation code **cc** to the user. The **cc** is a deterministic, truncated BLAKE2b hash of the Onion Service public key of the contact.

11. The user types the **cc** to the Transmitter Program which completes the key exchange.

Any messages received from the participant who completed the key exchange first, are cached by the slower participant's Receiver Program until that participant has also derived the keys.


##### Fingerprint verification design

Fingerprints are human readable values intended to verify the key exchange was not under a Man-in-The-Middle attack (MITM). MITM attacks can not be solved by cryptography itself, thus it is paramount that the users check their fingerprints match.

The fingerprints verified in step 6 above are presented in the decimal format to make pronunciation fast and easy in any language. We believe the proper balance between convenience and security is to always display the fingerprints and ask the user to verify them, but not force them to do so. Transmitter Program stores the public key fingerprint pair into the contact database. Fingerprint verification can be skipped by pressing <kbd>Ctrl</kbd> + <kbd>C</kbd> in the "Did the fingerprints match" `y/n` prompt. This sets the fingerprint verification status as `(Unverified)`. The fingerprints can be verified at later point with the command `/verify`. 

If a MITM attack is detected during the fingerprint comparison, users should select `No (=keys did not match)` which aborts the key exchange. In such a scenario there are few options.

* They should try again later (which results in different Tor circuit) 
* If the users know each other in real life and are able to, they should meet and exchange PSKs.
* Only if the users have no other contacts, they could also try deleting the `$HOME/tfc/user_data` directory and starting fresh with completely new Onion Service addresses. This will destroy all user data, keys, and logs, and should be avoided.

TFC uses well-thought-out design for fingerprints: Instead of just using hashes of public keys, fingerprints are domain separated, derived keys: they cannot be correlated with public keys without knowing the X448 shared key. To understand the security benefit, assume a scenario where the fingerprints users compare are regular hashes of public keys. In a situation where the Networked Computer running Tails has been compromised to the point the adversary can monitor public keys the Source Computer outputs via the serial link, the adversary can associate the public key with a particular endpoint but isn't able to tell to whom the endpoint belongs. 
    
Now, suppose the adversary is also eavesdropping and transcribing 
(
[1](https://theintercept.com/2015/05/05/nsa-speech-recognition-snowden-searchable-text/),
[2](https://theintercept.com/2015/05/11/speech-recognition-nsa-best-kept-secret/),
[3](https://theintercept.com/2015/06/08/nsa-transcription-american-phone-calls/),
[4](https://theintercept.com/2018/01/19/voice-recognition-technology-nsa/)
)
calls: They can record the spoken fingerprints and associate them with the person to whom the phone is registered. Since fingerprints are hashes, the adversary can generate an endpoint-to-public-key lookup table and by hashing the public keys, add fingerprint for each endpoint. To deanonymize the endpoint, all the adversary needs to do is perform a reverse-lookup. 

To prevent this attack, fingerprints in TFC are not hashes, but domain separated subkeys, in other words, keyed hashes of public keys. As the adversary does not know either participants' X448 private key ( **K<sub>S</sub>** or  **K<sub>S'</sub>**), they do not know the X448 shared key. Without the shared key, the attacker is unable to derive the fingerprint from the public key, and so, correlate endpoints with real-life identities of callers.


### Pre-shared keys (PSKs)

X448 is not future-proof because quantum computers are making their way (albeit slowly). In future, a 2688-qubit universal quantum computer will be able to break the key exchange with Shor's algorithm, which makes retrospective decryption of conversations, the symmetric keys of which were agreed with X448 trivial to break. The choices for post-quantum key exchange algorithms are limited, and those with strong security proofs such as McEliece with Goppa codes have very long (up to 1Mbit) keys. These keys work fine with applications that run on networked TCBs but are infeasibly long to type by hand in systems such as TFC. Until trustworthy post-quantum algorithms with short keys are found, TFC users looking for post-quantum security are stuck with pre-shared symmetric keys.

While PSKs are not practical in all cases (especially if the contact lives across the world), the people who would use TFC are assumed to be close to one another and to have at least occasional face-to-face meetings during which PSKs can be exchanged. PSKs have effectively indefinite lifetime, so even an expensive trip to perform the key exchange might be worth it. The last thing to consider is the key authenticity: The highest assurance against MITM attacks is obtained in physical meetings, and exchange of removable media containing pre-shared keys is even easier than verifying public keys aloud or comparing QR-codes.

The PSK exchange protocol is as follows.

![](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/13_psk.png)
[Pre-Shared Key protocol](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/13_psk.png)

**NOTE**: In the explanation below, a single quote `'` is used to denote data from the contact.

1. The Transmitter Program generates message key **K<sub>M</sub>**, header key **K<sub>H</sub>** and salt **S**.

2. The Transmitter Program prompts the user to enter and confirm a PSK encryption password **Pwd** that will be told to the contact.

3. The Transmitter Program derives key encryption key **K<sub>KE</sub>** from **Pwd** and salt **S** with Argon2id. The Argon2's `memory_cost` is fixed to 512 mebibytes to allow interoperability with low-end hardware (such as netbooks) the contact might be using. To ensure long key derivation times, `time_cost` is fixed to 25 to make derivation slow, but not unbearably so.

4. The Transmitter Program encrypts **K<sub>M</sub>** and **K<sub>H</sub>** using **K<sub>KE</sub>** to create ciphertext **CT<sub>PSK</sub>**. It then prompts the user to insert a `clean` never before used removable media into the Source Computer, into which the Transmitter Program then stores **CT<sub>PSK</sub> || S** under file name such as

        u5oeq.psk - Give this to s7tcr
        
    where `u5oeq` is the first five characters of the user's TFC-account and `s7tcr` is the first five characters of the recipient's TFC-account.

5. The Transmitter Program encrypts contact's TFC-account, nick, **K<sub>M</sub>** and **K<sub>H</sub>** using the local key **K<sub>L</sub>** to create **CT<sub>Tx</sub>**.

6. The Transmitter Program outputs **CT<sub>Tx</sub>** to the Receiver Program via the Networked Computer.

7. The Receiver Program decrypts **CT<sub>Tx</sub>** using **K<sub>L</sub>** and stores contact's TFC caccount, nick, **K<sub>M</sub>** and **K<sub>H</sub>** to contact and key databases.

8. The users exchange removable media in a physical meeting. The passwords **Pwd** and **Pwd'** protecting **CT<sub>PSK</sub>** and **CT<sub>PSK'</sub>** should also be exchanged somehow. For example

    * Verbal exchange during the meeting where the keyfiles are exchanged.
    
    * Verbal exchange over an end-to-end encrypted call (e.g., Signal, the security QR-code of which was scanned during the key exchange meeting).
    
    * Delivery on a separate security device (e.g., a [Yubikey](https://www.yubico.com/)).
    
    * **Passwords should not be included on PSK delivery media itself. This prevents a single point of  failure for PSK deliver. Furthermore the PSK already contains the 256-bit salt that is essentially the same thing.**

9. The user places the removable media of the contact to their **Destination Computer** and issues the command `/psk` to their Transmitter Program. The program forwards the command to the Receiver Program that then opens the PSK selection prompt. The user selects the PSK file from the removable media.

    #### WARNING! If the user connects the contact's PSK transmission media into their Source Computer instead of their Destination Computer, all security of the user's TFC endpoint must be assumed to have been lost permanently. This is because the Source Computer might now have been infected, and it might export private keys to the Networked Computer when the user is not looking.
    
    #### WARNING! If the PSK is exchanged with an untrustworthy contact whose device contains malware and a covert wireless exfiltration channel, all security is again, lost. PSKs must never be exchanged with people the user does not know well. A wise precaution is to copy the PSK file from the thumb drive to the Destination Computer's disk and to remove the thumb drive before even starting TFC.

10. The user enters the password **Pwd'** as told by their contact into their Receiver Program, using the keyboard of the Destination Computer.

11. The Receiver Program derives the key decryption key **K<sub>KE'</sub>** from the contact's password **Pwd'** and salt **S'**.

12. The Receiver Program decrypts **CT<sub>PSK'</sub>** using **K<sub>KE'</sub>** and stores contact's **K<sub>M'</sub>** and **K<sub>H'</sub>** to its key database.

13. The Receiver Program displays a confirmation code **cc** to the user. The **cc** is a deterministic, truncated BLAKE2b hash of the Onion Service public key of the contact.

14. The user types the **cc** to the Transmitter Program which completes the key exchange.

Once the keyfile is imported from removable media, it is overwritten with the tool [shred](https://linux.die.net/man/1/shred), and the user is advised to physically destroy the PSK transmission media to ensure forward secrecy of keys, and that no data leaves the Destination Computer. 

The user must always assume the contact's removable media/Yubikey etc. contained malware that exfiltrated sensitive keys and logs of the user on the device. Thus, the device(s) must never be returned to the contact, and they must be destroyed physically. **It is the responsibility of the contact to know they can not have their device(s) back.**


## End-to-end encrypted group conversations

In TFC, a group conversation is nothing but an agreement between multiple users to make their Transmitter Program multi-cast messages and files to each member of the group and to create a new window to their Receiver Program, into which the members are allowed to redirect their private messages. Redirection is requested by prepending the message with a group message header and the group's 4-byte ID. The prepending happens automatically when the group is active. Window creation, management, and selection also happen automatically with encrypted commands, whenever the user edits the members of the group or selects the group.

When the user selects a group, all message and file packets sent to the members of that group are encrypted with the message key that would be used to encrypt private messages to that member. Regardless of to how many packets a message had to be split, it will be delivered to one group member at a time. The design means some members will receive the message sooner than others. However, having the ability to send the message successfully to as many users as possible takes priority over keeping the conversation synchronized. For example, would the serial interface disconnect from the optocoupler for a moment, multiple group members would lose the ability to decrypt the long message, as one or more assembly packets would be dropped for each of them.

TFC allows the user to choose whether the members of the group are notified about the user adding/removing contacts to/from their side of the group. Removed members by design never get a notification about them being removed. If the user adds a removed contact back to the group and notifies them about it, only an invitation to join the group is displayed to that contact.

Messages about leaving the group are gentlemen's agreements. For example, in a group of three members, Alice, Bob, and Charlie, say Bob leaves the group and sends a notification about it to the two other members. The Relay Programs of Alice and Charlie will, in that case, display a message that Bob has left the group, but the program will also warn them that unless they remove Bob from their side of the group, any message they send to the group should be assumed to be still readable by Bob. Bob does not even have to modify his Receiver Program to do that. All he needs to do is join back to the group and not send a notification about it to the contacts; Since by design, groups use the same keys used in private conversations with the contacts, preventing this kind of 'eavesdropping' would require proprietary software clients which is again a horrible idea, and still not safe from a skilled reverse-engineer.


## Removal of metadata

Below is a dissection of different types attacks to obtain metadata about user activity. These attacks are performed by two different types of attackers: Eve is an eavesdropper who is monitoring traffic at ISP level. Mallory is a malicious active attacker who has compromised the Networked Computer and is observing what inputs the computer receives from the network, Source Computer, and local peripherals, and what it outputs to the Networked Computer's screen and to Destination Computer.

The amount of metadata TFC leaks depends on whether traffic masking is enabled. When it is enabled, Transmitter Program will output a constant stream of noise messages to Receiver Program of the selected contact or members of the selected group. 

![](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/14_traffic_masking.png)
[Traffic masking overview](https://www.cs.helsinki.fi/u/oottela/wiki/security_design/14_traffic_masking.png)

In the dissection below, if traffic masking setting affects the end-result, the implications of both setting values are discussed.

<details>
  <summary><b>Real-life identity of the user</b></summary> 

Since Relay Program reveals nothing about the identity of the user or their contacts, the identity of the user is not revealed even to Mallory. However, as any personal files on Networked Computer can reveal the identity of the user, use of Tails live USB (that does not store personal files) is highly recommended. Registration details of Networked Computer's hardware can also deanonymize the user, so the use of commercial off-the-shelf (COTS) hardware paid with cash is highly recommended.
</details>

<details>
  <summary><b>Geolocation of the user</b></summary> 

Networked Computer is a normal computer, that comes with an ever-increasing number of sensors from Wireless interfaces to GPS antennas, microphones, web cameras and so on, that can deanonymize the user or reveal their location to Mallory. Stripping all sensors is highly recommended. An additional layer of anonymity can be obtained by connecting to a random public WiFi access point using a long-range parabolic or Yagi antenna.
</details>

<details>
  <summary><b>IP address of the user</b></summary> 

Debian based Networked Computer does not force all connections via Tor by default, so it can trivially reveal the user's IP-address to Mallory. Use of Tails OS (that enforces Tor routing) on Networked Computer is highly recommended. This is because on Tails, [special care has been put to whitelist applications' rights to request e.g. the public IP address of the endpoint](https://github.com/Whonix/onion-grater).
</details>

<details>
  <summary><b>Type of data transmitted</b></summary> 

When traffic masking is disabled, sent files appear to Eve as large bursts of Tor cells. The burst will indicate a file transmission, but it requires a traffic confirmation attack. Mallory on the other hand, can see when the user outputs files.

When traffic masking is enabled, the Source Computer will output messages and files inside assembly packets, amidst noise packets. As all these packets look identical to Mallory, the type of transferred data is hidden from both Eve, and Mallory.

Traffic masking makes an exception to packet output order: when a long message or file is sent to the group, each contact will receive multi-packet transmission roughly at the same time. The reason for this is because to hide the length of the message, each member of the group must receive one packet at a time. One way to see this is, it would be pointless to send a noise message to all other members while one contact receives the long transmission.
</details>

<details>
  <summary><b>Social graph of the user</b></summary> 

Regardless of traffic masking setting, Eve learns nothing about the social graph of the user. However, Mallory can see to which call signs (Onion Services) the user talks to, as well as what kind of groups the user has formed from them, and when the user talks to the group. Mallory will not be able to learn whether an incoming message from a contact is a private message or a group message, unless she has also compromised the Networked Computer of the sender. However, as long as Mallory is unable to determine the real-life identity of users, their social graph remains hidden.
</details>

<details>
  <summary><b>Quantity and schedule of communication</b></summary> 

When traffic masking is disabled, Eve only sees that a burst of Tor cells was uploaded to the network. However, Mallory can see when and how many messages the user sends to each contact.

When traffic masking is enabled, Source Computer will output a constant stream of noise messages to Networked Computer. To prevent the user from accidentally revealing interaction with contacts, changing the active recipient of messages is disallowed. That way TFC hides quantity and schedule of output messages from both Eve and Mallory. It should be noted, however, that the use of Networked Computer reveals to Mallory that the user is present. It does not indicate TFC is being used, unless the user interacts with the TFC's Relay Program (e.g., if the user closes and reopens the application).
</details>

<details>
  <summary><b>Message length</b></summary> 

When traffic masking is disabled, Eve can only see Tor traffic, but Mallory can see how many packets Source Computer outputs to each contact. However, since TFC applies compression and padding to round the length of the compressed message to the next 255 bytes before encryption, Mallory does not learn the exact length of message or file.

When traffic masking is enabled, even Mallory will be unable to tell when message or file transmissions start or stop. The moment the transmission of a message or a file completes, the next packet will again be a noise packet.
</details>

<details>
  <summary><b>Existence of Onion Server and the fact TFC is used</b></summary>

Assuming Eve does not know the full TFC account, she is unable to decrypt the blinded Introduction Points in the Onion Service descriptor to establish a connection to the server.

Since Mallory is assumed to have control over the Networked Computer, she both knows the Onion Service's address and that it represents a TFC endpoint. However, since each TFC user looks like a typical Tor user, it is difficult for her to know which computers she should compromise in the first place. The fact it's hard to even figure out who is using TFC (and where they are physically located) makes proximity attacks very difficult.
</details>

## Traffic masking design

Under the hood, the Transmitter Program handles traffic masking with five processes: input process, sender process, two instances of noise packet generator processes and a logging process. The input process adds headers and padding to message, file, and command assembly packets, and places them into either message, file or command queue. The noise processes fill noise queues with noise packets. Both the input process and noise packet generator processes place identical tuples of data into the queue.

The sender process is an infinite loop that loads a boolean value for message, file and noise queues' status, and based on the result, picks the highest priority queue that has a 255-byte long block of plaintext data waiting. Selecting the queue is done by list indexing which is constant time (Python is a high-level language, so guarantees are hard to make). The queues are loaded under a ConstantTime context manager to reduce the attack surface further: The actual runtime of the function is much shorter on platforms that meet the minimum system requirements of Ubuntu 20.04 (Dual Core 2GHz, 4GB RAM).

Once a file or message packet is loaded from a queue, it will be sent to the selected recipient or members of the selected group. The recipient is selected (and locked) when traffic masking mode is enabled, or when the Transmitter Program is started (assuming traffic masking setting is enabled). The delivery of the packet is again done under the ConstantTime context manager that obfuscates slight variations in timing (XChaCha20-Poly1305 is a constant time cipher, but Python code around it might not be). To add even more security, the constant time context managers delay value is altered with a random amount specified by the kernel CSPRNG. Between each sent packet, the sender process checks under separate constant time context manager if a command is available, and based on that information either outputs the awaiting command, or a noise command.

All output packets are forwarded via multiprocessing queue to the logging process that will determine whether the packet will be added to the log file. Using separate processes prevents issues with i/o blocking that might affect the sender process, and reveal when TFC is being used. If logging for contact is enabled during traffic masking, only sent messages are logged. If the setting `logfile_masking` is also enabled, user's Transmitter and Receiver Programs will log all other sent and received packets (excluding commands) as placeholder data. This includes both whispered messages, and file/noise packets. The purpose of logging whispered messages as placeholder data is to hide the fact whisper messages have been sent: it's impossible for the physical attacker to determine from the ciphertext that it message wasn't in fact a noise packet.

The Receiver Program handles noise packets from all contacts without any alterations to settings. To maintain the per-packet forward secrecy, the Transmitter Program will have to re-derive keys between each message, which is troublesome. If the Networked Computer or the Destination Computer of any recipient goes offline for extended periods, catching up with the hash ratchet state after coming back online might take quite some time. The only existing solution for this is to ensure client uptime. The problem can be mitigated by ensuring Destination Computer has a fast CPU. A future consideration for better efficiency in hash ratchet performance is switching to BLAKE3, which is even faster than BLAKE2 currently used.


## File transmission

TFC sends files differently depending on whether the traffic masking is enabled or disabled.


##### File transmission without traffic masking

When traffic masking is not enabled, the Transmitter Program compresses and encrypts the file, and outputs the ciphertext to the Networked Computer together with a list of all the TFC accounts that should receive a copy of the file. Transmitter Program will then send each recipient a `file key delivery message` that contains the 32-byte BLAKE2b digest of the nonce, file ciphertext, and the related tag. The message also contains the file decryption key. This format allows multicasting the file with Relay Program. The decryption key for each contact is identical, but existential forgeries are not possible, as any alteration to the plaintext will produce a different ciphertext, the hash of which will not be found on the recipient's `hash : file_decryption_key` dictionary. As the Receiver Program will discard the file key from the dictionary immediately after file decryption, replay attacks with file packets are not possible. 

There is another reason to use same the symmetric key for each recipient: Mallory who has compromised the Networked Computer can with high probability link the encrypted files together. The reason she can do that is no efficient padding scheme can hide the exact file size. Thus, all ciphertexts of the same file the Source Computer outputs will be of the same size. Multi-casting different looking, roughly equal length ciphertexts sequentially would not fool Mallory -- it would only slow down file transmission and increase the duration the file transmission reserves the serial interface.


##### File transmission with traffic masking

When traffic masking is enabled, the Transmitter Program compresses the file, concatenates decryption key to enable sender based control over partially delivered data, splits the ciphertext into assembly packets and delivers them to the recipient(s). This process is identical to transmission of long messages, but the content is different as are the packet headers. Files are usually large, thus outputting them can take a very long time. During traffic masking messages have higher priority than files, so the sender process outputs packets from the message queue first. This makes it possible to send messages while the file transmission takes place on the background (i.e., when no message is being transmitted).


## Attacks against TFC

### Source Computer pre-compromise

Compromise of the Source Computer completely undermines the security of TFC. To protect the user, the installer `install.sh` is authenticated with a 4096-bit RSA signature, the verification key of which is imported only if the SHA256 digest of the public key file matches the digest embedded to the installer one-liner. The installer configuration for Relay, and local testing look identical to the installer configuration of the TCB configuration, until the point where the TCB configuration automatically cuts all network connections. This happens as soon as all dependencies have been downloaded to minimize the window of opportunity to compromise the system. The idea here is to hide the purpose of the device that would otherwise be revealed by the traffic shape, until it's too late to compromise the TCB. Hopefully this forces the attacker to attempt compromise of all three computers in order to compromise the Source Computer, and hopefully, such louder attack would also be easier to detect by a vary user.

If the user is targeted by a nation-state actor during the setup and Source Computer is undetectably compromised, **no security can be achieved**. The attack applies to all secure communication tools that are obtained from the network. The compromise can, however, be detected to a limited extent: If a packet analyzer such as Wireshark is used to monitor traffic during installation, the amount of data in the .pcap file to audit will be finite. Additionally, as the Source Computer is unable to determine what’s on the receiving side of the data diode, the receiving end can be plugged into a spectrum analyzer. These devices can see hidden signals because no information is missed: the displayed output is the result of FFT calculations. Since optocouplers are not analog, analyzing the output of optocoupler's Rx-side should trivially reveal covert channels, as any signal that turns the Tx-side LED on enough to activate Rx-side photodiode, will raise the Rx-side V_OUT to Vcc (5V).


### Destination Computer remote exploitation

Even though the Receiver Program does its best to drop invalid packets and authenticate all ciphertexts before decryption and handling, a constant window of opportunity remains to exploit the Destination Computer with a carefully crafted packet that might exploit, e.g., a buffer overflow vulnerability in the serial interface's driver, CPython, or PySerial library. The malware delivered as payload might then show arbitrary messages in the TFC program. These messages are however very likely out of context, as there is no way for the adversary to obtain knowledge about the content of plaintexts. This is again, because the Source Computer (the adversary can't send malware to) only outputs ciphertexts the adversary on Networked Computer has no decryption keys for, and because neither keys nor plaintexts can be exfiltrated from the Destination Computer. Additionally, if Bob's Receiver Program showed forged messages and logging is enabled by both parties, the attack can be detected by cross-comparing Source Computer side log of Alice with Destination Computer side log of Bob and vice versa. To detect malware that displays different messages than it logs, an extensive audit stage -- where messages are either videotaped or observed in real time -- is needed.


### Exfiltration of data via covert channels

Unaddressed covert channels could be used to exfiltrate data from the split TCB:

* The user might reuse removable media used to deliver PSKs. In such case the Destination Computer could infect the Source Computer that could then exfiltrate sensitive data. The PSK transmission media from an untrustworthy contact might also contain a covert transmitter.

* The user might forget to remove wireless interfaces such as Wifi, LTE, Bluetooth, and NFC from Source or Destination Computer. The interface could then be used to infiltrate malware and exfiltrate keys with the malware. 

* In addition to these channels, multiple covert ones -- that could leak or be used to exfiltrate keys from Source or Destination Computer -- have been found:
     
    * Malware could exfiltrate data from the Destination Computer with emissions
        * Electromagnetic channels (eavesdropped by the antenna of a nearby smartphone/implant)
            * Memory bus ([GSMem](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-guri.pdf))
            * Video card pixel clock ([AirHopper](https://ieeexplore.ieee.org/document/6999418))
            * USB cable as an antenna ([USBee](https://arxiv.org/pdf/1608.08397.pdf))
            * GPIO/UART/PWM ([Funtenna](http://www.funtenna.org/CuiBH2015.pdf))
            * Magnetic fields ([MAGNETO](https://arxiv.org/pdf/1802.02317.pdf))
        * Thermal channel (eavesdropped by a nearby temperature sensor / thermal camera)
            * Artificial workload ([BitWhisper](https://arxiv.org/pdf/1503.07919.pdf))
            * HVAC systems connected to TCB-side network ([HVACKer](https://arxiv.org/pdf/1703.10454.pdf))
        * Power lines (eavesdropped by tapping into the main electrical service panel of the building)
            * Controlled power consumption ([PowerHammer](https://arxiv.org/pdf/1804.04014.pdf))
        * Acoustic channel (eavesdropped by a nearby microphone or laser microphone that has line-of-sight)
            * Fan pitch changes ([Fansmitter](https://arxiv.org/pdf/1606.05915.pdf))
            * Mechanical drive (ROM, HDD etc) sounds ([DiskFiltration](https://arxiv.org/pdf/1608.03431.pdf))
            * Inaudibly high sounds from speakers to mics ([O`Malley, Choo](https://aisel.aisnet.org/cgi/viewcontent.cgi?referer=&httpsredir=1&article=1168&context=amcis2014), [Hanspach, Goetz](http://www.jocm.us/uploadfile/2013/1125/20131125103803901.pdf))
            * Inaudibly high sound from speakers to speakers ([MOSQUITO](https://arxiv.org/pdf/1803.03422.pdf))
            * Motherboard capacitor squeal ([Genkin, Shamir, Tromer](https://www.cs.tau.ac.il/~tromer/papers/acoustic-20131218.pdf))
        * Optical channel (eavesdropped by a camera in the space / outside the window)
            * ROM drive tray position ([CDitter](https://www.anfractuosity.com/projects/cditter/))
            * Invisibly fast blinking of screen ([VisiSploit](https://arxiv.org/pdf/1607.03946.pdf))
            * The light of scanner ([Nassi, Shamir, Elovici](https://arxiv.org/pdf/1703.07751.pdf))
            * Lights in USB keyboard ([Veres-Szentkirályi](https://techblog.vsza.hu/posts/Leaking_data_using_DIY_USB_HID_device.html))
            * Monitor's LED indicator ([Sepetnitsky, Guri, Elovici](https://ieeexplore.ieee.org/document/6975588))
            * HDD LEDs ([LED-it-GO](https://arxiv.org/pdf/1702.06715.pdf))
            * Router lights if connected to TCB-side network ([xLED](https://arxiv.org/pdf/1706.01140.pdf))
            * Security camera IR LEDs if connected to TCB-side network ([aIR-Jumper](https://arxiv.org/pdf/1709.05742.pdf))
    * Source or Destination Computer might unintentionally leak sensitive data to nearby smartphone, device or implant
        * Acoustic leak of messages/keys typed with the keyboard
            * Smartphone accelerometer ([(sp)iPhone](https://dl.packetstormsecurity.net/papers/general/traynor-ccs11.pdf))
            * Networked Computer speakers/headphones ([SPEAKE(a)R](https://arxiv.org/pdf/1611.07350.pdf))
        * Electromagnetic leaks
            * Display / keyboard cables ([van Eck phreaking / TEMPEST](https://www.cl.cam.ac.uk/~mgk25/ih98-tempest.pdf))
            * CPU Cores ([ODINI](https://arxiv.org/pdf/1802.02700.pdf))


### Covert channel based on user interaction

There exists a possibility, where an attacker could compromise the Destination Computer in a way that makes the device display some message based on key data. The user's reaction to that message on the Source Computer that is visible either to Networked Computer (i.e., when traffic masking is disabled) or to the recipient (i.e., when the attacker is also a contact), can leak key data to the adversary. The only way to prevent this is to use traffic masking and to vet contacts carefully.

TFC mitigates against the different variations of this attack to the furthest extent:

1. The first variant is a timing attack, where malware on the Destination Computer delays the display of received public key by, e.g., an hour. If the first bit of the key to be exfiltrated is 1, the attacker who monitors the Networked Computer can determine that bit by reasonable confidence if the user (re-)initializes the key exchange and outputs a public key to the Networked Computer after one hour. This attack is prevented by displaying received public keys on Relay Program only.

2. The second variant is a timing attack, where malware displays or delays messages from a friendly contact, and looks for effect on the user's replies to the contact. This attack is mitigated by having the Relay Program determine the timestamp when the message packet was received, and deliver that information to the Destination Computer, where the Receiver Program will display it next to the message content. The timestamp is displayed with 10ms resolution. The user can detect this variation of the attack if
    1. receiver Program displays the message with identical timestamp much later than the Relay Program, or
    2. no packet with the exact same timestamp exists on the Relay Program's ephemeral packet log.

3. The third variation is oblivious exfiltration of key data to an adversary on the Networked Computer. If the malware on the Destination Computer makes the Receiver Program display a message such as

    > Hey Bob, add my friend David: davidw6wvfxqjqknntxrt6rw3ngwt6hqeqrcgldu47miq2xfzfqhqsid

    what could happen is, such contact does not exist at all. Instead, the displayed account is the onion-URL encoding of a sensitive key such as the root-state of the local key (or the local key decryption key) the malware on the Destination Computer is trying to exfiltrate. If the user adds this account as a contact with the Transmitter Program, the Relay Program cannot tell the difference when it tries to connect to the purported Onion Service. However, the attacker on the Networked Computer can try to decrypt commands with the account and its hash ratchet states. Due to the possibility of such an attack, **the user should never add contacts displayed only by the Receiver Program**.
    
    Instead, the user should always receive the account (also) through some other way, such as the Relay Program, Ricochet, Signal conversation, or a phone call. In other words, the account must be received via at least one source other than the Destination Computer. The additional source proves the account is not a sensitive key. The same also applies to theoretical group management messages malware on Destination Computer could spoof. The bundled unknown accounts might represent sensitive keys. Another related matter is **the user should never join groups the group ID of which did not (also) originate from Relay Program's group invitation message.** I.e., if the user sees a message from a contact like 

    > Hey Bob, join our group "cypherpunks" under group id "2de6sbn1tCH4R" with David and Eric
    
    the group ID might contain part of sensitive key data. If the user adds the group and sends a group management message about it to each contact, Mallory can see that key data from the Networked Computer of the user. Thus, like TFC accounts, the group ID must come from the Relay Program. (While the group ID could be delivered to the Destination Computer inside an encrypted message, it would provide an effective exfiltration channel for frenemies that have compromised user's Networked Computer and Destination Computer.)
    
    Group IDs are random and unlike in, e.g., Signal, they are not secret, because on Networked Computer, Mallory can see the user output a message to a bunch of contacts, and determine they form a group. Knowing the group ID does not give any privileges to anyone, not even to a contact of the user unless the user has added the contact to members of the group.


### Shoulder surfing

TFC allows the user to quickly clear all screens with command <kbd>space</kbd>, <kbd>space</kbd>, <kbd>enter</kbd>. Messages can then be re-displayed with the command `/msg <nick>`. If the user wishes to clear the ephemeral message log, they can issue the command `/reset`. The user can also enable the setting `double_space_exits` on Transmitter Program to enable panic exit functionality that resets all screens and closes TFC. This preventing, e.g., impersonation and log file access without the master password. With the setting on, the command `/clear` can still be used to clear TFC screens. The highest protection against physical threats is achieved with `/wipe` command that requires the user to confirm the erasure. The command overwrites all user data on all three computers and powers them down. With full disk encryption and DDR3 memory, this should offer sufficient protection against cold boot attacks.

Clearing or resetting the Relay Program display on Networked Computer is disabled during traffic masking to prevent an adversary who has compromised Networked Computer from figuring out commands are being issued. During traffic masking, the clear-command actuation speed depends on command packet queue length. Also depending on delay settings, it might take a while before the screen clearing command is delivered to the Destination Computer.


### Malicious file delivery

File reception in TFC is disabled by default for all contacts, and it must be manually enabled. Receiver Program does its best to show the user what kind of file is being received, but this information is gentlemen's agreement and can trivially be spoofed by the sender. GNU/Linux offers robust security and requires the user to add the execution permission to received binaries and to execute them manually. However, zero days might still cause problems: Malware sent by frenemies can again, cause data loss or make Receiver Program show arbitrary messages.

Some defense against malware running with user level privileges comes from the side channel resistance of X448, XChaCha20-Poly1305 and Argon2id. To ensure the malware is not able to [eavesdrop on e.g. keyboard inputs](https://theinvisiblethings.blogspot.com/2011/04/linux-security-circus-on-gui-isolation.html), users should use the [Wayland](https://en.wikipedia.org/wiki/Wayland_(display_server_protocol)) display server instead of [X11](https://en.wikipedia.org/wiki/X_Window_System). 

TFC's default setting `max_decompress_size` limits the size of received data (after decompression). The default max value is 100 megabytes. The limitation protects the user against zip bombs in received files (as well as in messages).


### CT-only attack

The computational security of 256-bit XChaCha20 protects messages against brute force attacks.
 

### Existential forgeries

The computational security of 128-bit Poly1305 MAC protects against existential forgeries.


### Replay attacks

The Receiver Program stores the value followed by the most recent accepted hash ratchet counter value to the key database and raises a replay-attack warning if a previous hash ratchet counter value ever repeats. Additionally, as a new MAC key is derived for every message, the older authentication and decryption key no-longer exists: Even if the counter could be bypassed, the MAC verification would still fail as the message key that works has already been overwritten.


## Error tolerance

### Serial interface data transmission errors

Both Transmitter and Relay Programs add adjustable Reed-Solomon erasure code to all datagrams sent over the serial interface. The erasure code allows reconstruction of packet even in the cases of significant errors during the transmission.

Whereas short transmissions can be trivially resent, long transmissions have to be canceled first. The recipient should notify the sender if errors occur between their Networked and Destination Computer so that the sender can cancel and restart the transmission; Unfortunately the physical architecture of TFC makes automatic requests for packet re-transmission impossible.

Since Reed-Solomon introduces computational overhead, users who experience no errors with their hardware can disable it by setting error correction to 0. This will switch TFC to use BLAKE2b-based error detection checksums with truncated 16-byte digests.


## Code quality and secure programming practices


#### Type annotations

TFC is type checked with [mypy static type checker](http://mypy-lang.org/) to improve code quality.
Currently running the checker with `--strict --ignore-missing-imports` flags yields no warnings.


#### Unittests

TFC uses Travis CI with unittest coverage report to improve stability and security of the software. Cryptographic functions and the TFC API are tested with official test vectors. The links to the official sources of test vectors are listed in the docstrings of related unittests. 

TFC's code has 100% coverage with 0 skips. The tests are however still a work in progress in terms of readability and meaningfulness. 

#### Code quality metrics

Code quality is checked with [pylama](https://github.com/klen/pylama) that combines among other things
* [pycodestyle](https://github.com/PyCQA/pycodestyle) PEP8 style guide checker. Style is [a personal preference](https://www.youtube.com/watch?v=wf-BqAjZb8M#t=2m50s) and TFC aims for readability over rules.
* [PyFlakes](https://github.com/PyCQA/pyflakes) error checker
* [Mccabe](https://nedbatchelder.com/blog/200803/python_code_complexity_microtool.html) [cyclomatic complexty](https://en.wikipedia.org/wiki/Cyclomatic_complexity) checker
* [Pylint](https://pylint.org/) style and error checker
* [Radon](https://github.com/rubik/radon) metrics tool

Online code quality is further checked with following tools:
* [CodeFactor](https://www.codefactor.io/repository/github/maqp/tfc)
* [Codacy](https://app.codacy.com/manual/maqp/tfc/dashboard)


#### Error handling

For error handling, TFC uses EAFP where race conditions are a significant issue and LBYL where readability counts more. In any unrecoverable situation, TFC raises CriticalError, which terminates processes and gracefully exits the program. 


#### Pinned library hashes

TFC's installer `install.sh` contains a list of pinned SHA512 hashes for TFC source files. These include the PIP `requirements*.txt` files that contain pinned SHA512 hashes for dependencies. The dependencies downloaded over APT are verified only with associated certificates. Exfiltration security of private keys of third parties are unfortunately unfixable by us, but TFC downloads APT dependencies first to minimize the attackers' reaction time for [MOTS](https://en.wikipedia.org/wiki/Man-on-the-side_attack) or MITM attacks.


#### PGP signed installer and private key security

TFC installer is signed with PGP using a 4096-bit RSA key. The private key is generated, and the code is signed with a permanently air-gapped system to ensure exfiltration security of PGP private key. The SHA256 fingerprint of this public key file is the root of trust for the installation. The signature verification key is automatically authenticated with the digest by the one-liner used to install TFC. 


#### Shell-injection immune code

All `subprocess.Popen()` function calls with variable data use `pipes.quote()` to prevent shell injection from user's Transmitter Program. Functions used in processing received packets from contacts never contain Popen calls.


#### SQL-injection immune code

All SQL-queries use the database API's parameter substitution to prevent SQL-injections. Furthermore, every SQL-query comes from a trusted source, and processing of received packets from contacts never contain SQL-queries.


#### Principle of least privilege

Files accessed with `open(<filename>, <permissions>)` have minimum write/overwrite permissions.
