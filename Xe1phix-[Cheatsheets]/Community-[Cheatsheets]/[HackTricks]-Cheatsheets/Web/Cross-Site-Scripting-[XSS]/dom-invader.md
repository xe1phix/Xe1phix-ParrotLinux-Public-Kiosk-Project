# DOM Invader

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## DOM Invader

DOM Invader is a browser tool installed in Burp's inbuilt browser. It assists in **detecting DOM XSS vulnerabilities** using various sources and sinks, including web messages and prototype pollution. The tool is preinstalled as an extension.

DOM Invader integrates a tab within the browser's DevTools panel enabling the following:

1. **Identification of controllable sinks** on a webpage for DOM XSS testing, providing context and sanitization details.
2. **Logging, editing, and resending web messages** sent via the `postMessage()` method for DOM XSS testing. DOM Invader can also auto-detect vulnerabilities using specially crafted web messages.
3. Detection of **client-side prototype pollution** sources and scanning of controllable gadgets sent to risky sinks.
4. Identification of **DOM clobbering vulnerabilities**.

### Enable It

In the Burp's builtin browser go to the **Burp extension** and enable it:

<figure><img src="../../.gitbook/assets/image (4) (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

Noe refresh the page and in the **Dev Tools** you will find the **DOM Invader tab:**

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Inject a Canary

In the previous image you can see a **random group of chars, that is the Canary**. You should now start **injecting** it in different parts of the web (params, forms, url...) and each time click search it. DOM Invader will check if the **canary ended in any interesting sink** that could be exploited.

Moreover, the options **Inject URL params** and Inject forms will automatically open a **new tab** **injecting** the **canary** in every **URL** param and **form** it finds.

### Inject an empty Canary

If you just want to find potential sinks the page might have, even if they aren't exploitable, you can **search for an empty canary**.

### Post Messages

DOM Invader allows testing for DOM XSS using web messages with features such as:

1. **Logging web messages** sent via `postMessage()`, akin to Burp Proxy's HTTP request/response history logging.
2. **Modification** and **reissue** of web messages to manually test for DOM XSS, similar to Burp Repeater's function.
3. **Automatic alteration** and sending of web messages for probing DOM XSS.

#### Message details

You can click each message to view more detailed information about it, including whether the `origin`, `data`, or `source` properties of the message are accessed by the client-side JavaScript.

* **`origin`** : If the **origin information of the message is not check**, you may be able to send cross-origin messages to the event handler **from an arbitrary external domain**. But if it's checked it still could be insecure.
* **`data`**: This is where the payload is sent. If this data is not used, the sink is useless.
* **`source`**: Evaluates if the source property, usually referencing an iframe, is validated instead of the origin. Even if this is checked, it doesn't assure the validation can't be bypassed.

#### Reply a message

1. From the **Messages** view, click on any message to open the message details dialog.
2. Edit the **Data** field as required.
3. Click **Send**.

### Prototype Pollution

DOM Invader can also search for **Prototype Pollution vulnerabilities**. First, you need to enable it:

<figure><img src="../../.gitbook/assets/image (5) (1) (1) (3).png" alt=""><figcaption></figcaption></figure>

Then, it will **search for sources** that enable you to add arbitrary properties to the **`Object.prototype`**.

If anything is found a **Test** button will appear to **test the found source**. Click on it, a new tab will appear, create an object in the console and check if the `testproperty` exists:

```javascript
let b = {}
b.testproperty
```

Once you found a source you can **scan for a gadget**:

1. From the **DOM** view, click the **Scan for gadgets** button next to any prototype pollution source that DOM Invader has found. DOM Invader opens a new tab and starts scanning for suitable gadgets.
2. In the same tab, open the **DOM Invader** tab in the DevTools panel. Once the scan is finished, the **DOM** view displays any sinks that DOM Invader was able to access via the identified gadgets. In the example below, a gadget property called `html` was passed to the `innerHTML` sink.

## DOM clobbering

In the previous image it's possible to see that DOM clobbering scan can be turned on. Once done, **DOM Invader will start searching for DOM clobbering vulnerabilities**.

## References

* [https://portswigger.net/burp/documentation/desktop/tools/dom-invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)
* [https://portswigger.net/burp/documentation/desktop/tools/dom-invader/enabling](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/enabling)
* [https://portswigger.net/burp/documentation/desktop/tools/dom-invader/dom-xss](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/dom-xss)
* [https://portswigger.net/burp/documentation/desktop/tools/dom-invader/web-messages](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/web-messages)
* [https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution)
* [https://portswigger.net/burp/documentation/desktop/tools/dom-invader/dom-clobbering](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/dom-clobbering)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
