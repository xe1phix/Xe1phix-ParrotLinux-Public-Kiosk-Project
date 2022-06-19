# Mullvad-LinuxSetup

## [+] Xe1phix's Mullvad+OpenVPN Tutorial


[?] The only VPN providers I have ever trusted were riseup.net, mullvad, and recently ProtonVPN.
    Since riseup failed to update their canary, one must assume the source is compromised.
[?] Like iptables, you must implement a deny-all, allow by exception policy with trust.


## Mullvad Features:

    Mullvad supports DNS leak protection
    Mullvad supports Teredo (IPv6 over IPv4) leak protection
    Mullvad supports IPv6 tunneling as well as IPv6 blocking and leak protection
    Mullvad supports OpenVPN on a range of custom ports, including but not limited to 53/udp (DNS), 80/tcp (HTTP), 443/tcp (HTTPS)
    Mullvad only supports the VPN protocols OpenVPN and Wireguard
    Mullvad does not block authenticated SMTP
    Mullvad does not block P2P
    Mullvad blocks SMTP port 25/tcp because of spam
    Our data encryption is AES-256
    We run our own public key infrastructure (PKI)
    We support SSH tunneling, Shadowsocks, and Stunnel through our bridge servers
    All our OpenVPN servers use 4096 bit RSA certificates (with SHA512) for server authentication
    All our OpenVPN servers use 4096 bit Diffie-Hellman parameters for key exchange
    All our OpenVPN servers use DHE for perfect forward secrecy
    OpenVPN re-keying is performed every 60 minutes
    All our OpenVPN servers offer all available data channel ciphers on all ports, including AES-256-GCM, AES-256-CBC, and BF-CBC. AES-256-GCM is the default.
    Mullvad meets the privacytools.io criteria


[?] For a better understanding of the importance the VPN provider plays 
    watch Zoz's presentation at defcon: 
https://www.youtube.com/watch?v=J1q4Ir2J8P8#t=14m35s


[?] Mullvad has a great blog post on the fundamentals of privacy
https://mullvad.net/en/blog/2016/12/5/privacy-universal-right/


[?] Mullvad swore an oath to uphold the following: 

[+] The UN's Universal Declaration of Human Rights (articles 12 an 19) 
http://www.un.org/en/universal-declaration-human-rights/

[+] The European Convention on Human Rights (articles 8 and 10).
http://www.echr.coe.int/Documents/Convention_ENG.pdf



## [+] Further hardening techniques:

[+] Online-Privacy-Test-Resource-List (Known Fingerprinting Techniques)
https://github.com/CHEF-KOCH/Online-Privacy-Test-Resource-List




 ## [+] Privacy Quotes:

"What surveillance really is, at its root, is a highly effective form of social control,"

"The knowledge of always being watched changes our behavior and stifles dissent. 
The inability to associate secretly means there is no longer any possibility for free association. 
The inability to whisper means there is no longer any speech that is truly free of coercion, real or implied. 
Most profoundly, pervasive surveillance threatens to eliminate the most vital element of both democracy and social movements: 
the mental space for people to form dissenting and unpopular views."


