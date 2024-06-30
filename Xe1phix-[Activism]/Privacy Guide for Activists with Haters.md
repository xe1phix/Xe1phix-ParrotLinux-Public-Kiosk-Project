<h1>Privacy Guide for Activists with Haters</h1>
In light of the gamergate fiasco, we realized that most of the targeted individuals had their private information trivially publicly online. Later, several authors had more immediate experience with online harassment. This guide is meant to help people take basic steps required to protect their online privacy, hopefully reducing the number of crazies who threaten to show up at your house.

We do not believe that leaving your information online means you deserve harassment, we simply wish to arm people who want to speak up with all the defensive tools available.

This guide is not an anti-government-surveillance document, as it only helps you make your information private and does not remove it. Fighting back against surveilance is a very different problem, and there is a [separate guide for that.](https://gist.github.com/bluehat/76a07a5d25f038a89f3b99c54a9a94a9)

<h2>Hiding Your Whois Data</h2>
This one should be easy, but it is the number one privacy failure we found when checking information of individuals who have previously been harassed.

When you register a domain, you fill out contact information which by default is **public**. You can trivially check what information is public in any Linux/OSX terminal

    whois example.com

If you're not a machine which supports the whois command you can use one of the many [online tools](http://www.whois.net/) to check your the whois records.

If your personal information is available, we advise you to take one of the following actions:
* Purchase WhoisGuard for your domain from your registrar
* Purchase a domain by proxy plan and have them handle your domains
* Migrate to a registrar which provides free domain name privacy (namecheap gives it for free your first year)

Whois data isn't generally publicly cached, so once you fix this you should be good to go! It sometimes technically can be stored by certain services behind a paywall.

<h3>Advanced Whois Chaos</h3>
If your information is on your whois but out of date, put some of it through [reverse whois tools](http://www.expertusability.com/reverse-whois-search/). A matching phone number or email address can be used to find other domains registered with that information, and those records might be current.

<h2>Removing location data</h2>
While most activists are very good about this, no guide would be complete without it!

* [Disabling web location and removing your old location data on Twitter](https://support.twitter.com/articles/122236#)
* [Disabling mobile location on mobile devices](https://support.twitter.com/articles/118492-using-the-location-feature-on-mobile-devices#)
* [Disable location services on iOS](http://support.apple.com/kb/ht5594)
* Unfortunately, due to the way android phones are made, the camera app is normally different for each manufacturer, and so you will have to look up directions specific to your phone's make.

<h2>Removing EXIF data</h2>
EXIF data is a variety of information the device which captures your photo stores and uploads with your photo. If this device contains a GPS chip (like almost all cellphones do) the location where the photo was taken can be determined. [The EFF has a longer explanation](https://www.eff.org/deeplinks/2012/04/picture-worth-thousand-words-including-your-location) if you're curious.

* Twitter, Facebook and Tumblr remove sensitive photo EXIF data by default, but not all services do. 
* If you'd like to see what EXIF information a  site shows, take the URL of an image uploaded there and put it in [this website](http://exifdata.com/).
* Flickr permits you to upload information with EXIF data. Consider disabling it when you post from sensitive locations.
* If you have an anonymous persona, strip all EXIF data from all photos you upload. A device ID can link your public and private personas.
* Imgur automatically strips all sensitive information, so when in doubt, they are safe and awesome!

<h2>Searching by Images</h2>
If you recycle the same profile images over and over, you may be surprised what shows up if you [search by your profile image](http://www.google.com/insidesearch/features/images/searchbyimage.html).

<h2>Miscellaneous</h2>
* Don't hotlink images directly from Facebook unless you're OK with everybody knowing your Facebook profile.
* If you discuss your partner(s) or housemates publicly, remember to make sure they follow this guide too.

<h1>Make your accounts harder to steal!</h1>
<h2>2 Factor Authentication</h2>
We're sure you've been lectured on password security, and while your habits are probably terrible, we're going to focus today instead on 2-factor auth. 2-factor auth requires somebody to know your password **and** have your phone or another physical device (or at least control over it). 

You're encouraged to enable 2-factor authentication on everything, but **prioritize accounts where password resets are sent**.

Here is an [amazing website with directions on how to do 2-factor auth on everything ever](https://twofactorauth.org/).

<h2>Update where password resets go</h2>
Check through your old accounts. Do you still own the old @hotmail.com where you registered your twitter handle 7 years ago? If you don't, somebody can register that name and take your password reset! Make sure your account recovery options go to a safe location. You can read as many postmortem security reports you need to to get the picture: **this is the most common way somebody gets control of your online persona.** First they take the account where your main account (probably your gmail) goes to, they reset that password, then they login to your main account (probably your gmail) and the go to town. **Even if you don't put a 2-factor setup anywhere else, put it on the primary email where all your password resets go.** If your password resets go all over the place, pick one account, send all the password resets there, and turn on 2-factor there.

<h2>Proper unique passwords</h2>
Remember how you thought your terrible habits would never come back to bite you? If you're reading this, you are obviously reconsidering that stance.

Convincing you to be an adult overnight is probably a lost cause, so install a password manager. [KeePass](http://keepass.info/) is the choice of open-source hippies (like me), while [LastPass](https://lastpass.com/) and [1Password](https://agilebits.com/onepassword) are commercial options.

Whenever possible, set up and use ssh keys instead of passwords.

<h1>Disaster Response</h1>
So you now have the internet's full attention. What precautions can you take to minimize damage? These measures are not for daily use as they are rather inconvenient, but more of a disaster response plan if, for example, your haters get out of hand enough to merit national television reports.

<h2>Switch to a physical 2FA device</h2>
Since your phone can be hacked, you may want to consider a physical 2FA device. We don't endorse any particular one, but check it is compatible with the services you plan to use it on.

<h2>Freeze your credit</h2>
You can place a freeze on your credit, thereby preventing people from taking out new debts or credit cards in your name. You will need to freeze your credit with each of the 3 major credit burearus: [Experian](http://www.experian.com/consumer/security_freeze.html), [Transunion](http://www.transunion.com/securityfreeze) and [Equifax](https://www.freeze.equifax.com/Freeze/jsp/SFF_PersonalIDInfo.jsp) Please note: this is a pretty dramatic step. You should read about what it means to freeze your credit and consider the ramifications before doing it. You will also inconvenience yourself significantly if you'd like to take out any new loans or credit cards because you can't do that when you freeze your credit.

<h2>Get rid of all debit cards</h2>
If you debit card information is stolen, an attacker can clean out your entire account and the onus is on you to get things back to how they were. Credit cards are required by law to have far more strict rules, and you have a lot more options to control the situation. Ask your bank to give you ATM-only cards and credit-only cards. Sometimes this requires going to the bank in person and speaking to humans, but it is pretty easy to do. Warning: You now need either an Amex card or cash to go to Costco.

<h2>Disable all remote wipe settings</h2>
Your phone, tablets, and computers generally have settings to remove all of your data using only an internet connection. You normally enable these things because you believe your posessions are more likely to be stolen than the internet is to come hunting for you. When that calculation changes, it is time to disable any settings which permit remote wipes. [Apple products are notoriously sensitive to this issue.](http://www.emptyage.com/post/28679875595/yes-i-was-hacked-hard)

<h2>Remove dropbox and any other systems which can read or write to your hard drive</h2>
We all love the conveniences of remote cloud backups which appear as folders in our system, but if these systems are compromised, an attacker has [full access to everything on your computer](http://www.polygon.com/2014/8/22/6057317/fez-developer-polytron-hacked-harassment) and the capacity to delete it. 

<h2>Opt out of 3rd party data retention</h2>
If you find that you are removing your data online, particularly whois, you may want to consider opting out of the people searching services which store that data online for purchase. Some of them require you to pay them to do this or provide very personal information. That is bad behavior and they should feel bad. There is also an entire 3rd party market for paying services to remove your data. Reddit has compiled [a list](https://www.reddit.com/r/technology/comments/j1mit/how_to_remove_yourself_from_all_background_check/) of major companies and how to opt out, though we don't have experience working with these companies, some seem shady, and some of the info seems out of date.

<h2>Get on the Do Not Call List</h2>
Many harassers don't make the calls themselves but instead sign you up as interested for potential services, and then have those services disrupt you. Getting on the [Do Not Call List](https://www.donotcall.gov/) will severely diminish the number of calls that get through.

<h2>Traditional identity theft</h2>
While rare for those facing online abuse, this absolutely is possible if enough information about you becomes public. [/r/personalfinance has an excellent guide on their wiki](https://np.reddit.com/r/personalfinance/wiki/identity_theft). Thankfully, many of the steps are things you were probably doing already from this guide.

<h1>The Bad News</h1>
* If you own property, your address is a matter of public record. Sometimes you have to go to the office or call them to get it, but it can be legally obtained
* If you are registered to vote, your contact information can be accessed by any Super-PAC in most states. Becoming one costs about $300 and the records cost $15 to obtain
* Utility bills in your name, while they are not suppose to be something you can trace, often can be traced
* Your cell phone may well be a weak point in your 2FA plan, especially via text. Some providers have sub-par security and permit you to read your texts online. You can get a new text number from one of many online services and simply not give it out to anybody to mitigate this. Google Voice does not work with all 2FA systems.
* You currently need to begin Apple's 2FA process super early because they have a waiting period.

<h2>What you can do</h2>
* Use a fake last name

<h1>Ways to help even if you are not experincing online harassment</h1>
* Petition your government to make citizen privacy a priority
* Petition sites you love to enable 2FA
* Petition Apple to remove their waiting period. Katy wrote [a letter](https://medium.com/p/apple-please-update-your-2fa-and-support-policies-to-protect-those-experiencing-online-harassment-f95c4265a966) for you to send if you like.

<h1>About</h1>

This privacy guide is made by [Katy Levinson](https://twitter.com/katylevinson) and a privacy-concerned friend. It was debugged with love by Katy's former coworkers at [Crooked Tree Studios](http://throwtrucks.com/), [Cliff Jolly](https://twitter.com/expiredpopsicle) and [Chris Meyer](twitter.com/cygnil).

This work is licensed under a [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-nc-sa/4.0/), though we'd prefer that you just submit patches to [this gist](https://gist.github.com/bluehat/354432b82650d0a722ed). If you want to give us money for this public service, [give it to the EFF instead](https://supporters.eff.org/donate).