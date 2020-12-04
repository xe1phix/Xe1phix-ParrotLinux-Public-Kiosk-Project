# A Citizen's Guide to Digital Freedoms

# 0: Background

## 0.0: What and Why
We're about to hand the architecture for a surveillance police state over to new leadership. Some of Trump's language around free speech and free press has been troubling, and a [campaign advisor has already threatened a reporter](http://www.cnn.com/2016/11/13/politics/kellyanne-conway-harry-reid-lawsuit/). This seems like an excellent time for us to create nontechnical educational information on how technology can be used to protect citizen's civil liberties.

The goal of this guide is to create lesson plans which nontechnical people can then use to run classes for groups of nontechnical people. This guide will not make you safe. It will increase your chances of remaining safe for longer. **If you are running Windows 10, or a Lenovo laptop, please skip to 4.0 for a discussion of your options before attempting to secure these machines.**

## 0.1 Help Needed

Calling this a rough draft would be generous. Help is appreciated, especially from: 
 1. More technical people to provide content.
 1. Nontechnical people to explain what areas are not clear.
 1. People who can make illustrations and diagrams to make complicated concepts simple
 1. People with teaching experience to help figure out how to break this into a course people can teach each other
 
## 0.2 Ownership and Distribution

This work is licensed under a [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-nc-sa/4.0/), though we'd prefer that you just submit patches to [this gist](https://gist.github.com/bluehat/76a07a5d25f038a89f3b99c54a9a94a9). If you want to give us money for this public service, [give it to the EFF instead](https://supporters.eff.org/donate). All Amazon links include the EFF referral tag, so they get money.

This information is kept in git format because it is easy to transmit git repos peer-to-peer. You are encouraged to download a copy. Suggestions on how to keep the guide trustworthy and from having merge issues in a peer-to-peer environment are appreciated. 

## 0.3: Security, Authentication, Encryption, and Expiration

### Security
Security means that your messages can't be understood by anybody except the party you are sending them to.

### Authentication
Authentication means the person who is getting your messages is the person you want to have your messages. Most security technology will successfully auto-establish a secure connection on its own, but you need to take extra precautions to make sure you are talking to the correct person on the secure channel.

### Communication Encryption
We are working with public key cryptopgraphy. Public key cryptography is like an old-time wax seal people used to seal letters, except it actually works.

To keep it simple: you have two things called keys, but which are actually large (hundred+ digit) numbers. One is called your public key, and one is callled your private key. 

Your private key is like the stamp which makes your wax seal: it is used to sign documents. If anybody ever steals your private key that is very bad. **You must protect your private key.**

Your public key is like the address of a secured mailbox.

The keys are inherrently linked. They are set up so that your private key (thing which makes your wax seals) is the only thing which can open your mailbox, and your public key (the address of your mailbox) can be used to verify the authenticity of the wax seal on your letters.

The one thing the math can not solve is making sure you do the setup work with the right person. Imagine you and your friend have never sent messeges each way before. The first thing you'd have to do is tell your friend where your mailbox is and show them how to verify your wax seal's authenticity. If you do this over the internet, you're basically sending a courier nobody's met before who is just going to show up and claim to be working for you. 

Your friend can't trust that courier. A bad person could catch the courier at a crossroads and start impersonating them. This would let them give your friend the address of a mailbox that they claim belongs to you, but really belongs to the bad guy. If they did this to both of you all the messages on both sides would be delivered instead to the bad person. If the bad person was diligent about forwarding the messages with their setup, you and your friend would never know there was somebody in the middle watching everything you do. This is why mailbox address / public key exchanges are normally done in person, or by a method which is built off a network of people verifying keys in person. In the security community, they are often added to people's business cards and twitter profiles.

This is why you need to worry about both security and authentication. The technology will make you secure, but you will always need to take precautions to make sure the person you think you are speaking with is the one you intended to speak with.

**Short Version: Your private key is very secret: way more secret even than your social security number ought to be. Your public key is something you can tell to whoever you want, like a phone number. Don't trust keys if you aren't sure they belong to your friends**

### Expiration

Over a long enough time, all crytography can be cracked. Your data can live on a disk as long time as computers improve. You should not keep logs you don't want found out, and you should use services which don't log whenever possible, but if a government is logging you, they can use the logs from their servers. You'll need to remember that cryptography is not hiding what you are doing from the government forever. Instead it is delaying the government's capacity to read what you say and do for a certain number of years. This is why if freedom of speech/press is gone for too long of a time, technology will begin enforcing its absence.

# 1: Communication Privacy

## 1.0: What is this and why?

The government, by default, collects a lot of information about you. Much of this is done through the [phone companies](https://www.theguardian.com/business/2016/oct/25/att-secretly-sells-customer-data-law-enforcement-hemisphere), but there are some serious allegations that more internet providers do this as well.

This section helps you communicate with other people while reducing your chances of having your message intercepted or tampered with.

## 1.1: Signal / Securing your SMS

Open source, peer-reviewed, and [endorsed by Edward Snowden](https://www.youtube.com/watch?v=j_kieJ-Ng2Q), [Signal](https://whispersystems.org/) is an easy first step for anybody interested in basic security. It has been on both the Android and iOS app stores for many years, and works with most phone OS versions.

Remember that until you have also authenticated your contacts using "verify safety numbers" (in the conversation settings on the android version) you can be sure whoever is getting your information gets it securely, but you will not have a guarantee that the person who is getting it is the person you want to get it.

Outside actors will be able to determine who you communicated with and when, but not what you said.

If your phone is hacked by something else (like maybe you downloading shady apps) your texts will still be readable by whoever has hacked your phone. That person could also gain access to your private keys.

If you get a new phone, you will currently have to re-do key exchanges. This is an issue with Signal, not with the underlying technology.

You can download signal on the app store or [through their website](https://whispersystems.org/).

## 1.2: Adding Encryption to Existing Messaging Protocols

### OTR for Pidgin / Adium

[Pidgin (Windows and Linux)](https://www.pidgin.im/) and [Adium (OSX)](https://adium.im/) are pieces of software used to connect to many kinds of messaging accounts at once. This means you can be active on more than one Google Talk / Hangouts account at once. Facebook messenger can also be routed through it. Time travelers will be happy to know you can also have this interface handle AIM, MSN, ICQ and a lot more. Adium and Pidgin happen to be the same system reskinned for different operating systems, but this is a common piece of software, and you can find lots of other pieces that do the same thing.

The Pidgin/Adium system has a great plugin called OTR, which is written by the group [Cypherpunks](https://otr.cypherpunks.ca/). OTR means Off The Record, and turns on encryption end-to-end with anybody else who has installed the plugin. Remember that authentication is a differnet problem than security, and that you should make sure any new keys actually belong to your friends before discussing anything really important.

When your messages are encrypted, if you have them synched to your phone or other non-encrypted views, they will look like gibberish on your phone because your phone will only see the encrypted version.

Here is [how you set up OTR on Adium](https://adium.im/help/pgs/AdvancedFeatures-OTREncryption.html). The Pidgin setup is a little bit more involved. [Windows has its own installer](https://otr.cypherpunks.ca/index.php#downloads) which you run separately. [Linux instructions](https://ssd.eff.org/en/module/how-use-otr-linux) vary by distribution, but generally there is a separate package for pidgin with OTR already installed that is handled by your package manager. 

Pidgin is not as reliable as it could be for video chat, mostly because certain platforms don't properly support video chat in their APIs. If you want to have a video chat, you may want to sign onto the client through the old way, and run the chat from there. It will not be encrypted. 

### XMPP

XMPP is am open-source messaging archiecture designed to be secure. Both Google Talk and WhatsApp started as forks of this platform, and to this day you can connect to talk with XMPP users through a Google Talk account. 

To run XMPP, you will need a client (Pidgin and Adium will work). You will also need your own server, or somebody else's server to connect to. Remember that if you don't trust whoever is running your server, you aren't that far ahead of using one of the existing corporate services.

## 1.3 Secured Messaging Protocols

Phones in particular do not have options like pidgin/adium, so here are some apps which will be alternative messaging options:

### Threema (iOS, Android, Windows Phone)

Threema is a secured messaging system which focuses on also granting anonyminity and runs a full stack in-house in Switzerland, a very free country by internet standards. You don't sign up with any personal information, and you can only add people by learning their IDs. You can download their app from the app store or [their website](https://threema.ch/en).

### Wickr (iOS, Android, Windows/OSX/Linux Desktop)

Wickr is a secured messaging protocol where messages disappear after a period, like Snapchat except with privacy. Also like Snapchat, it can occassionally be a little fussy until you get use to it. You can download it in the app stores or [on their website.](https://www.wickr.com/personal)

## 1.4: Encrypting Your Email

# 2: Anti-Censorship

## 2.0: Censorship Mechanics

Governments such as China outright block many websites outside their country. Governments like Pakistan are intercepting all outbound traffic before it leaves the country so they can watch it.

These measures are meant to help you keep access to content which a dictatorship does not want you to see.

## 2.1: VPNs 

A VPN, or Virtual Private Network, is essentially a computer based somewhere else. You make a secure tube from your internet to that other placem and look through it. You can use this computer to see whatever the internet looks like from the perspective of that computer. This means that if a website is blocked in your country, you can use a VPN to "get to the internet" in another country, and then see the website.

They are commonly used now to get around traffic shaping measures by your ISP (Internet Service Provider: aka Comcast etc). ISPs illegally throttle services like Netflix all the time, so opening a VPN to a colo means that they can't really traffic shape your encrypted data, they can only turn the speed up and down monolithically. VPNs are also used to make working on unsecured coffee shop wifi reasonable, and can be used to sidestep snooping by non-government actors, such as your school or workplace.

With a VPN, outside actors will still be able to see that you are sending data out of the country if they are watching the VPN. They will be able to tell who you are unless you somehow make it incredibly difficult for them to tell what computer is connecting to the VPN. If the VPN is compromised, outside actors will be able to see what you look at, and possibly change what you are looking at.

This is why you want the other end of your VPN to come out in a place not controlled by whoever you are concerned is spying on you.

To set up a VPN, you will need to get an endpoint (normally a rented machine in a data center) and to configure your computer so all traffic goes through that endpoint. We are working to figure out easy ways to make this technology accessible to less technical people. We reccomend [OpenVPN](https://openvpn.net/index.php/open-source/documentation/howto.html#quick). Other options are explained in [the AnonOps #OpNewBlood VPN tutorial](https://newblood.anonops.com/vpn.html), which is the best nontechnical VPN overview we have found. You may want to consider doing your own homework on what VPN provider you ultimately choose, since that website is accurate but a bit shady.

Iceland has shown an interest in being a center for digital freedom. Further research on the best VPN endpoints is appreciated, but for now, Iceland is advised for your endpoint.

## 2.3: Tor

# 3: Browsing Privacy 

## 3.0 What This Means

A lot can be inferred about you by looking at what you look at online. All of the techniques in the anti-surveillance section help with this, but here are some ways to keep your browsing more private.

## 3.1: HTTPS Everywhere (Firefox, Chrome, Android, Opera)

The EFF has created [a plugin](https://www.eff.org/https-everywhere) which always forces you to use the more secure version of a website when available. This means that people in the middle will be able to infer the domain name you are looking at (like www.example.com) but your behavior inside the website will be hidden. 

# 4: Information Distribution, Verification, and Storage

# 4.0: Distribution and Protection Needs

Government removal of information from the internet is becoming increasingly easy. The United States government already has the infrastructure and authority to [seize domain names](https://www.justice.gov/usao-sc/pr/federal-court-orders-seizure-67-website-domains-involved-smuggling-and-selling-misbranded), effectively removing sites from the interent. 

The normal solution to this is to use a decentralized information network. Bit Torrent is one of the protocols often used to do this. This solves the problem of any one central point of failure, but anybody can put a torrent up, so you don't know if it is trustworthy.

Unfortunately, knowing if you can trust a file you download is a problem we have everywhere on the internet. Malicious people can switch out files on your network. This is why we also have systems to verify that a file has not been tampered with in transit, and that it comes from where you think it comes from.

Once you have sensitive information, you need secure ways to store it.

### Known Compromised Systems

#### Windows 10
[Windows 10's EULA stipulates that everything you do on your computer will be logged by Microsoft, and that these logs will be available to the government.](http://www.newsweek.com/windows-10-recording-users-every-move-358952) This is why there will be a lesson in installing an option other than Windows called Linux.

Linux is not made by a single company. It has a core, and a wide variety of distributions have been built on that. There are conflicting borderline religious opinions on what distribution is best. 

#### Lenovo Laptops

Lenovo laptops have a [history of manufacturer-bundled malware](http://www.theregister.co.uk/2015/08/12/lenovo_firmware_nasty/) which opens a security vulnerability on the system if the system boots Windows. The code is injected before Windows launches. It is considered a backdoor on the system and it is baked into the physical boards they ship you. This practice has gone on for multiple years, and has caused some [US federal government branches to try to not use the systems anymore](http://www.wsj.com/articles/u-s-navy-looks-to-replace-ibm-servers-for-security-after-lenovo-purchase-1432047582). [Obama has required that several federal agencies get approval for any systems they purchase if the systems are made in China](http://www.reuters.com/article/us-usa-cybersecurity-espionage-idUSBRE92Q18O20130328), supposedly for this reason. 

#### Cell Phone USB Charger Rooting Issues

USB, the protocol by which most cell phones charge, has a strict master/slave protocol. That means that one end of the protocol has nearly complete control over the other. In the case of phones that use USB, your phone is always the slave. This means that anything you plug your phone into to charge can install malware on your phone if it has a computer chip in it and somebody can access that chip to put malware on it. [This includes iPhones](http://www.extremetech.com/extreme/157207-black-hat-hackers-break-into-any-iphone-in-under-a-minute-using-a-malicious-charger) even though the end of the USB cord looks different. Look out for USB chargers in airplanes, since their security in particular is extremely questionable and jerks have literally hours where they often have nothing better to do than root a whole planeful.

Since asking you to never charge your phone from anything with a chip ever again is a lot, you are advised to either [purchase](https://www.amazon.com/s/field-keywords=usb+data+block&tag=electronicfro-20) or [cut up an existing wire to make](http://www.instructables.com/id/How-to-make-a-USB-no-data-charger-cable/) a data block USB cable. They are casually known as USB condoms. This is a USB charger where the power lines connect to the device, but the data transmission lines are set up to not connect. 

If you want to transfer information from your computer to your phone, you will need another cable with the data lines intact.

## 4.1: Torrenting

## 4.2: Signatures and Checksums

## 4.3: Full Disk Encryption

## 4.4: Getting Rid of Data / Destroying a Hard Drive

This is probably not generally necessary, as you are unlikely to get federal agents interested enough in your computer to come put your hard drives back together, but the guide wouldn't really be complete without this.

### Data Erasure

Deleting files does not mean they are gone from your computer. It only means that you have told your computer they aren't there. Until another program overwrites the space with more data, anybody with the right tools can recover the information.

Even after you overwrite the data the first time, people with large amounts of resources can still recover data. A state police lab will easily have these resources. This is why there are programs on the internet which will write your drive to entirely zeros, or even random junk data to your drive over and over again for you. Running these over and over again will decrease the odds that data can be recovered, but will not guarantee it.

### Physical Destruction

Physically destroying the drives is a good option, and in most cases just smashing the part which store the data is enough. However, if you have [really attracted some attention to yourself](http://www.popularmechanics.com/technology/security/how-to/a8566/how-to-read-a-smashed-hard-drive-14877558/), you should know that the relevant pieces of data can be stored on extremely small pieces of the drive, so it can be difficult to make sure you have properly destroyed the drive. There are two kinds of hard drives, and each have different relevant parts to destroy.

#### HDD: Hybrid Hard Drive (Old Kind)

The data is kept on a circular object called a platter. If you open the case, it is the large circular thing. Remove it (you can smash it to make it easier to remove, but that won't do it on its own). Watch out for the magnets, which are strong enough to break fingers if they become dislodged and rush together with you in the middle. Make sure you leave nothing connected to the center, as your data takes up extremely small amounts of space.

#### SSD: Solid State Drive (New Kind. Sometimes in desktops, almost always in laptops)

When you access a solid state hard drive's board, you will see a bunch of black computer chips which are likely symetrically mounted. Your data is in there. You can pry the chips off the board with a flathead screwdriver.

//TODO picture of a SSD because this is confusing

#### Destruction

There are a variety of options out there, but you can always smash the storage portions stuff up until a paper shredder will finish your job for you. 

#### Disposal

The bigger trick is making the pieces hard to find. Your can always take a nice drive down the freeway and pour the little remaining fragments out a window.

# 5: Internet Anonymity

## 5.0: Need

## 5.1: Remailers

## 5.2: Your IP Address

## 5.3: What Is a Clean Computer?

## 5.4: Tails

Tails is [live CD/USB software](https://tails.boum.org/) which has a lot of preconfigured privacy and encryption software. This means you'll set up a drive, reboot your computer to use that disk as a hard drive, and when it turns back on, your computer will be secured by default. Then, when you turn your computer off again and remove the drive, you can turn it back on again and access your files on your hard drive as normal.

# 6: Anonyminity for in Person Work

## Facial Recognition Software

## IMSI Catchers

When your phone connects to a tower, the tower knows which phone it is. Police forces now have fake towers which will record all phones which connect to them. This can be used to de-anonymize protestors. 

The best defense (inconvenient as it is) is to have a cheap burner phone which you only use for political action. Android phones are available for ~$60 now.

## Filming Police Conduct

While a few areas have made this legally difficult (and you should check) the [ACLU has provided software which will automatically upload any video you take and send it to your local ACLU chapter.](https://www.aclu.org/feature/aclu-apps-record-police-conduct)

It is advised that you use an auto-uploading app of some type, as police often confiscate phones with incriminating evidence on them.

# 7: Legal 

## 7.0 Description
The primary author is not a lawyer, and none of the colaborators are known to be one either. This document is not legal advice. 

## 7.1 No Fingerprint Readers to Unlock Things

# 8: Contributing to Internet Freedom (Mostly Nontechnical)

## 8.0: Explanation

Since many of these services are decentralized or crowdsourced, you can contribute by running a piece of the network.

## 8.1: Running a Tor Exit Node

This is a huge service to the public, but **does sometimes expose you to harassment from the US federal government.** One of the greatest concerns about the security of Tor comes from the number of exit nodes which are controlled by the US government, so helping run more non-government nodes is a very big deal. Here is [Noisebridge's guide on responding to federal inqueries about their tor exit node](https://www.noisebridge.net/wiki/Noisebridge_Tor/FBI). 

Please seriously consider [running a Tor exit node](https://blog.torproject.org/blog/tips-running-exit-node), particularly if you live in a country with stronger civil liberties. 

## 8.2: Downloading and Storing Activist Information for Offline Distribution

## 8.3: Running a Bittorrent Mirror for Activist Information

## 8.4: Configuring Your Phone to Detect IMSI Catchers
