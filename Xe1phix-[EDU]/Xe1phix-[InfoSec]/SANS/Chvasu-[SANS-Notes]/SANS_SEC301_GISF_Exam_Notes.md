# DAY-1 Security Foundation
1.	Use CIA for prioritization
2.	Senior Manager
a.	.com -> CEO
b.	.gov -> commander, etc.
3.	Data Owner: Person with primary responsibility, determine classification and protection measures
4.	Data Custodian: People or group who implement decisions of owner
5.	Users: by default, they are also data custodian
6.	Types of attackers:
a.	Disgruntled Insider, Accidental Insider, External Insider
7.	Prudent person rule: did org act as a prudent person would act in protecting assets? CEO!
8.	Due diligence: Industry best practices considered prudent
9.	Due care: Actions that a reasonable person would exercise to protect assets
10.	Security requirements: MUST, SHALL, WILL
11.	Security guidelines: SHOULD, MIGHT, CAN
12.	Culture  Policy  Procedure
13.	By default, there is an “expectation of privacy” on the computer network.
a.	Unless the privacy policy says otherwise.
14.	GDPR  20m euros or 4% of global revenue, whichever is higher
15.	Separation of duties: Forces collusion; No one process has control of process from beginning to end
16.	Dual control: Two locks on same door; also called two-person integrity by DoD
17.	Reference checks: facts vs false claims
18.	Credential checks: certification or degree verification, etc.
19.	Background checks: legal / criminal checks, etc.
20.	Need to know = Read access; Least privilege = Capability
21.	Principle of least privilege can help to counter Ransomware
22.	Discretionary access control (DAC)
a.	Owner decides who should access and the level of access
23.	Role based access control (RBAC)
a.	User inherits permissions based on what’s assigned to role
b.	Sometimes violate principle of least privilege

# DAY-2 Computer Function and Networking
Hex:    A=10    B=11    C=12    D=13    E=14     F=15

LAN: Limited geographical area; Uses Ethernet protocol
WAN: Large geographical area; something other than Ethernet
MAN: Covers a city; Metropolitan area network
CAN: Covers buildings on campus
PAN: very small and personal
SAN: Storage, Robust part of LAN housing storage

NIC: Connects computer to network (has two addresses, hardware and IP address)
Switch: Forwards traffic to destination hardware addresses
Router: Forwards traffic to its destination IP address

NIC -> Switch -> Router -> Routers/Switches

Encapsulation: Process built into TCP/IP that cannot be changed

TCP/IP layers; Link -> Internet (IP) -> Transport (TCP/UDP) -> Application
IP -> best effort protocol (no guarantee of packet delivery, has error notification, no error correction)
Ephemeral ports start with 11 (49152 – 65535). Well-known and registered ports start other than 11.
IPv4 header packet as protocol value: (1 for ICMP, 6 for TCP and 17 for UDP)
UDP header has 8 bytes; TCP header has 20 bytes

# DAY-3 Introduction to Cryptography
Key: A numeric value of a given length
Keyspace: The range of values that can be used to construct a key
Cryptography doesn’t address availability.

Encryption -> Confidentiality of communication
Steganography -> Secrecy of communication (last 3 bits of JPEG are insignificant)

Transposition: Transpose | permute | obfuscate
Rail Fence (alternate letters), Scytale (wrap and unwrap), column shift

Substitution: Replace with letters or numbers:
	Monoalphabetic: Atbash (backward alphabet) | Caesar Cipher (C3) or ROT3 | 
		Spaces are retained in the above
		Susceptible to frequency analysis or cyphertext only attacks
	Polyalphabetic: Vigenere (Cipher Table, initially used repeating key; later used Running key (book))
		Ciphers replace letters but Code Book (codes replace words) 
	One-time PAD or OTP: Must be as long as the message (running key), unbreakable cipher, XOR

Effective Infinity: Very long time needed to break / brute force

Computers cannot generate a truly random value; thus Pseudo-Random number generator (PRNG)
	Guessing the next number in PRNG leads to Birthday attack

Mixcolumns: Permutation function on columns of text
Shiftrows: Rotational substitution function | Sub bytes: Arbitrary substitution function
Addroundkey: XOR function that modifies the key for each round

Snake Oil: An idea of no value but promoted as solution to a problem
Work factor: Time taken to decrypt an encrypted message
	(Key length, Randomness, Algorithm strength, Avalanche effect)
	The infinity work factor does not exist
Moore’s Law: Processing power can be doubled roughly every 2 years
Avalanche effect: Small change in input leads to significant change in output (e.g. hashing)

Windows uses MD4 to store password hashes.
MD series of hashes  Ron Rivest
SHA series of hashes  NIST  (SHA2 family: 224, 256, 384, 512 bits hash lengths)

Preimage attack: Predictable collision in hash
AES128 (10 rounds), AES192 (12 rounds), AES256 (14 rounds of encryption), 4 functions per round
Symmetric key algorithms: BLOCK CIPHER (DES (Lucifer algorithm), AES, etc.) or 
STREAM CIPHER (RC4, etc.)  preferred for ATM transactions
 	DES uses 56 bit key, 64-bit block size, 16 rounds of encryption
Asymmetric key: Possession of one does not allow the discerning of the other.
	Diffie-Hellman, RSA, ECC (only aym algo that is not based on prime numbers)

Signcryption = encrypt + sign
PKI is a framework, not a protocol
S/MIME encrypts both the email text and attachments!
FTPS: 989 (data) & 990 (control)
IPsec: Authentication Header (protocol 51, no encryption), Encapsulating Security Payload (protocol 50)

# DAY-4 Cyber Security Technologies Part 1

802.11a (5GHz: 54 Mbps)
802.11b (2.4 GHz: 11 Mbps)
802.11g (2.4 GHz: 54 Mbps)
802.11n (5 or 2.4 GHz: 450 to 600 Mbps) Wi-Fi 4
802.11ac (5GHz: 1.3 Gbps) Wi-Fi 5   (Jan 2014)
802.11 ax (possibly 4x throughput)   Wi-Fi 6

Do not use WEP (40 bit key to 128 bit key, could predict next encryption key) and WPA (uses Temporal Key Integrity Protocol (TKIP))

Can use WPA2 (or RSN, Robust Secure Network), supports AES256 (4 way handshake for key exchange)

WPA3 is coming (individualized data encryption, Robust pre-shared key protection, better IOT support, 192 bit DoD approved encryption)

Limitations to Wi-Fi encryption:
a.	MAC address cannot be encrypted (MAC spoof possible)
b.	Management frames cannot be encrypted
c.	Data encryption between wireless client and wireless access point only; after that it stays unencrypted

Wi-Fi pineapple: De-authenticate and spoof a legitimate network.
MAC-filtering for Wi-Fi, not for true security, but protects from certain users. Worth using it.
Do not stop broadcasting of Wi-Fi SSID. 

Wi-Fi Protected Setup (WPS): Router shares all security settings with the connecting client PC
	PIN mode, Push-Button mode, Near-Field communication or USB modes

Travel routers (Wi-Fi) ensure that your actual devices are hidden from the hotel / public network. The public network sees only the Wi-Fi router device. 
E.g. Slate (GL-AR750S-Ext) Dual Band Gigabit Travel Router

WarXing: Wardriving / Warwalking / Warparking / Warsitting / Warflying / Warbiking, etc.

Bluetooth: (Coverage limited but security point of view: ASSUME UNLIMITED DISTANCE)
Class 1: 100 mW : 100 Meters| Class 2: 2.5 mW : 10 Meters | Class 3: 1 mW : 1 Meter
	Cell phone headsets use Class 2
Piconet: Connecting the Bluetooth devices together
SSP: Secure Simple Pairing (4.1 and later); Uses Elliptical Curve Diffie-Hellman (ECDH) for key exchange
AES256 bit encryption in 4.1 version and above; Bluetooth WarXing: Blue Hydra tool
4 types:	
a.	Numeric comparison
b.	Passkey entry (manual) -> use 16 digits
c.	Just works
d.	Out of band (NFC)
USB seeding: Act of leaving USB devices in restrooms or public areas as a way to inject malware

There is no IOT security standards exist yet.
SCIP (Strategic and Competitive Intelligence Professionals) code of ethics

5 phases of an attack:
1.	Reconnaissance (passive) 2. Scanning (Active) 3. Gaining access (3.5 Privilege escalation) 4. Maintaining access 5. Covering tracks (Phase 5 is required for phase 4)

Cyber Kill Chain: 
	Reconnaissance: Weaponization: Delivery:  Exploitation: Installation: Command & Control (C2): Actions on Objections

How social engineering attack works?  Pretexting (reason given in justification that is not real) 
(most common) (direct and indirect)

Spear Phishing is the most lucrative single attack in the world today

Overall, users click on 1 in 20 phishing emails. 25% in 10 min; 50% in 1st hour; 90% in 24 hours

Watering Hole attack: Attacker uploads menu PDF with malware. Company downloads and opens it and becomes victims.

Lateral movement: Within organizations, moving from one PC to anther PC (during hacking)
Island Hoping: Moving across organizations

Memory address randomizers reduce buffer overflow attack to a large extent

DNS Cache Poisoning (DNS Spoofing) or Domain Hijacking (Social Engineering)

Malware:
Virus: Parasitic in nature / relies on other software to propagate
Worm: Self-standing, self-executing software (mostly targeting client operating systems, not servers)
Trojan horse: Software with known functionality and with unknown functionality (most common)
Logic bomb: time / date based event / preconfigured
Rootkits: Software that allows a hacker to get back into a compromised system, control its functions, etc. 
	Even admin cannot detect it. Easy backdoor access for hackers repeatedly.
Spyware: Records computer activity (browsing, keystrokes, etc.)

Cryptojacking: Fastest rising category of malware (4000% increase in 2018) (not much in raw numbers though) (victimless crime)

Ransomware: make data unavailable until ransom is paid
Ransomware Defense: Versioning Backups!

Malware Development Kits (Factories): Ransomware is the current leader (Ransomware Dev Kits). Point and click creation of malware

Polymorphic malware: Virus designed to self-modify to fool antivirus software
Retrovirus: Virus that attacks the anti-virus software
Multiparite: A virus that spreads through multiple mechanisms / multiple infection vectors

Antivirus software works in 2 categories of detection:
a.	Signature: database of unique strings
b.	Heuristics: watches for virus-like behavior (writing to boot sector of the drive)
Most antivirus software now include antispyware capability

Windows Defender: Supports Microsoft Antimalware Scan Interface (AMSI), which allows to scan fileless malware that only exists in memory, such as PowerShell code

Windows 7 and later has fully stateful inspection firewall (both ingress and egress) enabled by default
Mac has firewall but disabled by default

# DAY-5 Cyber Security Technologies Part 2

Compartmentalization: dividing into security zones (intranet, extranet, enclaves, etc.) for better security
Segmentation: dividing a network for efficient management (VLAN, Subnets, etc.)
Enclaves: Distinctly bounded areas enclosed within a larger area

Firewall types: Packet filter | Proxy | Stateful Inspection
(Always work on an ‘Exclusive Lookup’ basis) | Mostly default deny | On advanced logging in Firewall and tie into SNMP infrastructure.
    Shallow: Headers only (IP, Port, Protocol) | Data is not evaluated | Faster
    Deep inspection: Headers first (goes into data to decide permit or deny) | Slower but catches more
	
Packet filter: First ever made / text file / rules / only shallow (layer 3 and 4) / order of rules is important
Proxy: Layer 7 / Not through it: to it and from it / Latency a real problem, especially for UDP
Stateful inspect: Most common firewall type today | Packet filter with state table / engine | Many can do deep inspection
A packet filter firewall, by definition, will filter each and every packet it receives against its rule-list (i.e. access control list, a.k.a. ACL).

A stateful inspection firewall will evaluate the first TCP packet (with the SYN flag set) against its rule-set and accept or drop accordingly. TCP packets that indicate that they are a) completing the 3-way-handshake b) part of an established connection, or c) part of the graceful teardown OR immediate severing of a connection are assessed against the firewall's state-table first and depending on the results, allowed or dropped without the firewall needing to look at its rule-set.

A web app or proxy firewall are specific types of stateful inspection firewalls, each type requires knowledge of the state of a connection in order to perform its duties.

Stealth rule: 1st one: To protect firewall itself. Anyone trying to connect directly to firewall will be blocked.
Cleanup rule: Last one: Default deny, rarely logs
Firewall may also be doing NAT, IDS, IPS, Antivirus, etc.

DMZ or Edge network: Do not put a public access server on your internet network
Having a hot-swap server in DMS public access makes it easy for replacement and offline analysis in case of compromise

Sinkhole: 0.0.0.0 configuration on firewall / no one can access it

IDS: Signature based / Anomaly (out of normal) / Behavior based (weird cases)
IPS: IDS that stops attacks, if identified (Deep packet based)

Network scanners (NMAP) and Host scanners (Nessus): Generate huge reports (problem)
Exploit software: Metasploit and Core Impact

Offensive countermeasures: ADHD: Active Defense Harbinger Distribution (Linux with defense tools)
	Send attackers misinformation to misdirect   (Get legal advice)

Threat hunting: Assume bad guys are in – find them! (Indicator of compromise); GOAL: reduce dwell time (time between discovery and breach)

Web error codes: 200 OK | 300 Redirect | 400 Client error | 500 server error
Microsoft Edge: Called “Spartan” | Limited # of plugins
-	Runs with limited permissions
-	SmartScreen filter to block XSS
-	Tab isolation
-	Secure password storage
-	InPrivate browsing mode

Chrome:
-	Stores password in encrypted SQL database
-	Tab sandboxing (each page its own rending process)
-	Runs with extremely limited permissions
-	Anti-phishing and malware protection
-	Every 30 min connects to Google servers (list of known malicious sites to protect users)

Active content: business logic done on client side
A trapdoor becomes a backdoor, if not removed prior to releasing the software to production

Cloud Security: 
-	ISO17788: Cloud overview and vocabulary
-	ISO17789: Cloud Reference and Architecture
-	ISO19086-1: SLA Framework

Backups: 
Incremental (full backup + each day backup) | Differential (full backup + backup from last full backup)

Cloud based backup: Must use Zero-Knowledge for sensitive data
-	Zero-knowledge: data encrypted on local system and copied to cloud; Cloud provider has no knowledge of encrypted data

Sync.com and crashplan.com -> file backups with unlimited versioning

WSUS: Replaces Microsoft online update server
