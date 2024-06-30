> [[Wiki|Home]] ▸ [[Tor]] ▸ [[Onion services]] ▸ **Connecting to an authenticated Onion service**

An authenticated Onion service is a certain kind of [Tor "hidden service"](https://www.torproject.org/docs/onion-services) that requires clients (you) to supply an authentication token (basically, a password) before responding to incoming connection requests. There are a couple kinds of authenticated Onion services (`basic` or `stealth`). This page describes how to configure your software to connect to such a service, regardless of the Onion service's specific type.

> 💡 🔰 If you are trying to use Tor as a file sharing tool, consider following the instructions in [Secretly sharing files with OnionShare and TorBrowser](https://github.com/AnarchoTechNYC/meta/blob/master/train-the-trainers/mr-robots-netflix-n-hack/week-1/secretly-sharing-files-with-onionshare-and-tor-browser/README.md#readme) instead. [OnionShare's "Advanced" options will automate the server-side portion of creating a stealth Onion service](https://github.com/micahflee/onionshare/wiki/Stealth-Onion-Services).

> 💡 🌐 [See the Tor project's own site for instructions on configuring unauthenticated Onion services](https://www.torproject.org/docs/tor-onion-service).

# Contents

1. [Overview](#overview)
1. [Procedure](#procedure)
    1. [Laptop or desktop computer](#laptop-or-desktop-computer)
    1. [Android-based mobile device](#android-based-mobile-device)
    1. [Apple iOS device](#apple-ios-device)

# Overview

To connect to an authenticated Onion service, you must first acquire the access credentials (your personalized password) from whoever operates the service. This will likely be a human that you know. You will need to communicate with them (perhaps using [Signal](https://signal.org/)?) to learn what your access credentials will be. Once acquired, your access credentials will look something like the following line of text:

```
HidServAuth 1234567890abcdefg.onion abcdef01234567890+/K A description here
```

> ⚠️ 🔰 Do not put these credentials anywhere even remotely public. This includes sending yourself the credentials via e-mail. Saving these credentials anywhere that they could be obtained, by anyone else, defeats the entire purpose. And that would be silly.

This is a Tor configuration directive (a [`HidServAuth` directive](https://www.torproject.org/docs/tor-manual.html#HidServAuth)). It has four parts, separated by spaces, and it breaks down as follows:

1. `HidServAuth` - Designates that whatever comes next is the hidden service authentication credentials.
1. `1234567890abcdefg.onion` - Tells Tor which site the credentials you'll supply should be given to.
1. `abcdef01234567890+/K` - The authentication cookie value (the password) itself.
1. `A description here` - Optionally, you can include a descriptive comment to let *you* know for which site or service these credentials are intended.
    > 🔰 💡 If the Onion service is particularly sensitive, avoid including personally identifying information in the comment. For example, `Chris's message board` is an unsafe description. A better one might simply be, `Message board`.

On a typical computer such as a [laptop or desktop workstation, you will need to add this configuration line to your Tor's configuration file](#laptop-or-desktop-computer), called `torrc`. The configuration file tells Tor certain things about how it should operate, exactly like a settings screen. If you are [using an Android-based mobile phone](#android-based-mobile-device), you'll enter the Onion address and the authentication cookie value into an actual settings screen.

# Procedure

The exact procedure for setting up your Tor client to connect to a Tor server's authenticated Onion service varies slightly depending on the device you're using.

## Laptop or desktop computer

**Do this** to connect to an authenticated Onion service from your laptop or desktop computer:

1. Install Tor Browser from [TorProject.org](https://www.torproject.org/download/download-easy.html).
1. Acquire the access credentials you need from the Onion service operator. I.e., get in touch with them and ask them for access. If they do not respond, poke them until they send you your access credentials. :) 
1. Locate the `torrc` file that you need to edit. The location of this file is slightly different depending on your computer's operating system:
    > 🔰 In the following file paths, the `~` character or the `%HOMEDRIVE%%HOMEPATH%` sequence refers to "wherever your home folder is."
    * In *macOS*, edit `~/Library/Application Support/TorBrowser-Data/Tor/torrc`.
        1. Open a new Finder window.
        1. From the *Go* menu, select *Go to folder…*
        1. In the *Go to the folder* text box, paste `~/Library/Application Support/TorBrowser-Data/Tor/` and press the *Go* button.
        1. The `torrc` file will be one of the files in the window that opens.
    * In *GNU/Linux*, edit `~/[path_to_tor_browser]/Browser/TorBrowser/Data/Tor/torrc`.
    * In *Windows*, edit `"%HOMEDRIVE%%HOMEPATH%"\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\torrc`.
1. Open the `torrc` file with a text editor, such as [Notepad](https://en.wikipedia.org/wiki/Microsoft_Notepad) on Windows or [TextEdit.app](https://en.wikipedia.org/wiki/TextEdit) on macOS. Any [text editor](https://simple.wikipedia.org/wiki/Text_editor) will do. However, *Microsoft Word and other programs that expect rich text formatting will not work*.
1. Paste the configuration line you received from the Onion service operator on a line by itself in the `torrc` file.
1. Save the `torrc` file.
1. Restart (quit and re-launch) Tor Browser.

After re-opening Tor Browser, you should now be able to connect to the `.onion` address described in your `torrc` file (assuming, of course, that the Onion service hosts a website).

## Android-based mobile device

**Do this** to connect to an authenticated Onion service from your Android-based phone:

1. Install [Orbot](https://guardianproject.info/apps/orbot/). You can acquire Orbot from the Google Play Store or, preferably, from [F-Droid](https://f-droid.org/), a [Free Software](https://www.gnu.org/philosophy/free-sw.html) app store that offers most of the same apps as the Google Play Store, but free of charge.
1. Install [Orfox](https://guardianproject.info/apps/orfox/). You can acquire Orfox from the Google Play Store or, preferably, from F-Droid.
1. Configure Orbot:
    1. Tap the vertical ellipse menu at the top-right.
    1. Tap the *Hidden Services* menu.
    1. Tap the *Client cookies* menu item. The Client cookies activity screen will appear.
    1. Tap the compose button on the bottom-right of the screen.
    1. In the *.onion* field, enter the full Onion address (including the `.onion` suffix) of your Onion service.
    1. In the *Auth cookie* field, enter the full authentication cookie value as you received it. (The authentication cookie value is the third item in the `HidServAuth` configuration line, [described above](#overview).)
    1. Tap the *Save* button.
    1. Tap the back button (&larr;) in the top-left corner of the screen to return to Orbot's main activity screen.
1. Restart Orbot:
    1. Tap the vertical ellipse menu at the top-right.
    1. Tap the *Exit* menu item. This will fully close Orbot.
    1. Launch Orbot again. This time, Orbot will be able to connect you to the Onion service.
1. Launch Orfox.
    1. From Orbot's main screen, press the *Browse* button. This will launch Orfox if it is already installed.
1. Type in the Onion service URL (including the `.onion` suffix) into Orfox's Web address bar, then press *Go* on your software keyboard.

You should now be able to connect to the `.onion` address that you configured in Orbot's "Hidden Services" menu (assuming, of course, that the Onion service is a website).

## Apple iOS device

At the time of this writing, iOS cannot connect to authenticated Onion services. When available, [iCepa](https://github.com/iCepa/iCepa) may make it possible to connect to Onion services on devices running Apple's iOS.
