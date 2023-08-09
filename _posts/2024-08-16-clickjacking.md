---
layout: post
title: Clickjacking
excerpt: 
categories: [clickjacking, iframe]
---

**image**

Clickjacking is a type of web attack where an attacker tricks a user into unknowingly clicking on a malicious element on a website. This is done by overlaying or hiding the desired content behind a seemingly harmless element, such as a button or a link, which is usually designed to trick the user into clicking on it.

The goal of clickjacking is to deceive the user into performing unintended actions, such as sharing confidential information, downloading malware, granting permissions, or making a purchase. The attacker could manipulate the visibility or positioning of the desired content to mislead the user into taking actions they did not intend to take.

Clickjacking often exploits vulnerabilities in the web communication protocol, allowing attackers to frame legitimate websites within malicious websites or inject malicious code into trusted websites.

To protect against clickjacking attacks, web developers can implement measures such as using frame-busting scripts, employing X-Frame-Options headers in HTTP responses, or using Content Security Policy (CSP) to restrict the allowed sources of content.

Users can also protect themselves by being cautious while browsing the internet, avoiding suspicious or unfamiliar websites, and regularly updating their web browsers and security software to mitigate potential vulnerabilities.



<br>

###  Copy the benign website

In a clickjacking attack, the attacker's aim is to mimick the benign website as much as possible so that the victim cannot really tell that he/she is on a malicious website. One of the ways an attacker does this is to through an iframe.

An iframe (inline frame) is an HTML element that is used for embedding another HTML document within the current HTML document. Web pages use iframes to include external content such as videos, maps, social media feeds, advertisements, or any other web content without having to write the code into own HTML structure. The src attribute of the iframe specifies the website to be embedded and loaded into the iframe when the code is executed.

This task involves setting up a website `www.cjlab-attacker.com` to look like `www.cjlab.com` using an iframe. To achieve this, I do the followiwng:

- add an iframe to `www.cjlab-attacker.com` by adding the below code to the website index page.

  `<iframe src="http://www.cjlab.com"></iframe>`
 
- modify the webpage css file to make the iframe cover the whole page by adding the below to the css file

  ```css
  iframe {
    width: 100vw; /* occupy 100% of the viewport width */
    height:100vh; /* occupy 100% of the viewport height */
    border: none; /* remove borders from the iframe */
    position: absolute; /* ensure the iframe is positioned independently */
  }
  ```

- test the confuguration by loading the malicious website. From the screenshots below, we can see that the cloning was a success.

  ***`www.cjlab.com`***

  ***`www.cjlab-attacker.com`***

With the iframe inserted, the attacker's website `www.cjlab-attacker.com` looks like the benign website `www.cjlab.com`

<br>

### Position a button over the target area

With the website already cloned, the next step is to create a button that will reside over the iframe.

```css
button{
    /* Provided button code in SEED lab. */
    position: absolute;
    border: none;
    color: white;
    padding: 35px 35px;
    text-align: center;
    font-size: 40px;
    border-radius: 15px;
}
```

**image**

However, the malicious button needs to cover the target area (in this case, "Explore Menu") and needs to be invisible. To achieve this, I do the followiwng:

- modify the webpage css file to make the button cover the target area by adding the below to the css file

  ```css
  button{
    ... /* existing code snippet. */
    margin: 8em 0px 0px 1em; /* margin: top right bottom left */
  }
  ```

  **image**

- modify the webpage css file to make the button transparent by adding the below to the css file

  ```css
  button{
    ... /* existing code snippet. */
    color: rgba(0,0,0,0.0);  /* font color with full transparency*/
    background-color: rgba(0,0,0,0.0);  /* button's background color with full transaparency */
  }
  ```

  **image**

Comparing the appearance of the attacker's website `www.cjlab-attacker.com` to the benign website `www.cjlab.com` we can see that there is no surface evidence that a functioning clickjacking attack is present on the website.

When the victim clicks the "Explore Menu" button on the attacker's website, the victim is redirected to a page different from the action that is expected from the real `www.cjlab.com` website.

**image**

Consider this scenario. An attacker creates a fake webpage that mimicks a real website. J.Doe a victim, unknownly clicks the malicious link in the fake webpage thinking he is on the real webpage. As a result of clicking on that link, pornographic contents and propagandas get posted to J.Doe social media page. Now this can lead to not just undesirable consequences for the victim user, but very serious consequences.

This is to show how serious clickjacking if not prevented can be.

<br>

### Frame Busting

Frame busting also known as frame blocking is a security measure used to protect against clickjacking by preventing a webpage from being displayed within a frame on another website.

When a website uses frame busting, it ensures that the webpage is displayed as intended, and website owners can safeguard their content, user data, and ensure a more secure browsing experience for their visitors.

There are different methods for implementing frame busting. Some of them include:

Target="_top": Adding the target="_top" attribute to all links on the website ensures that the page is always loaded in the top-level browsing context, breaking out of any frames.

- JavaScript: this involves using a script that checks whether the website is being displayed within a frame. If it detects that it is embedded within a frame, the script instructs the browser to break out of the frame and load the page independently in the main browser window. Also, there are existing JavaScript libraries that have been specifically designed for frame busting, i.e. the Frame Buster library. These Javascript libraries can provide a ready-to-use solution for preventing framing.

if (window.top !== window.self) {
  window.top.location.replace(window.self.location.href);
}

- X-Frame-Options HTTP header: this involves setting the "X-Frame-Options" HTTP header with a value of "DENY" or "SAMEORIGIN". "DENY" ensures the webpage cannot be embedded in an iframe by any other site, while "SAMEORIGIN" allows embedding in an iframe by pages from the same origin.

- Content Security Policy (CSP): this involves implementing a CSP with the "frame-ancestors" directive which specifies what origins are allowed to frame the website.

- Server-side checks: this involves checking the "Referer" or "Origin" header of incoming requests on the server-side to identify if a website is being framed or not.

___

This task involves making changes to `www.cjlab.com`s index file to include Javascript code that will perform frame busting. To achieve this, I add the followiwng Javascript code to the index page of `www.cjlab.com`:

```javascript
<script>
    window.onload = function() {
        makeThisFrameOnTop();
    };

    function makeThisFrameOnTop() {
        // TODO: write a frame-busting function according to
        // instructions (Task 3)
        if (window.top !== window.self) {
        window.top.location.replace(window.self.location.href);
        }
    }
</script>
```


As seen from the screenshot below, when I navigate to the attacker's `www.cjlab-attacker.com`, rather that `www.cjlab.com` loading in an iframe, the website breaks out of the frame and loads independently. This means when the "Explore Menu" button is clicked, nothing malicious happens but the expected button action happens.

**image**

<br>

### Attacker Countermeasure against Frame-busting Script

This task involves exploring how an attacker can create a workaround for frontend clickjacking defenses like frame busting. This task makes use of adding the sandbox attribute to the malicious iframe too defeat frame busting.

Sandboxing is a technique that creates a virtual "box" area where application codes can run in isolation, without being able to access other parts of the system. In the case of an iframe, by setting the sandbox attribute, we can effectively tell the browser to run the iframe in a sandbox and isolate it from accessing other actions of the web browser. Thus the frame busting script is rendered ineffective as it will not be able to create any action outside of the sandbox.

To achieve this, I make the following adjustment to the iframe tag in the HTML code.

`<iframe src="http://www.cjlab.com" sandbox=""></iframe>`

As seen from the screenshots below, when I navigate to the `www.cjlab-attacker.com` after updating the iframe to use the sandbox attribute, the attack works. The frame busting script is rendered ineffective. Thus when the "Explore Menu" is clicked, the user is redirected to the malicious website to show that the attack is indeed working.

**image**

**image**

<br>



