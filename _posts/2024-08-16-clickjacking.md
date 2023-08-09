---
layout: post
title: Clickjacking
excerpt: Clickjacking is a type of web attack where an attacker tricks a user into unknowingly clicking on a malicious element on a website. This is done by overlaying the legitimate element with a transparent malicious element. To protect against clickjacking attacks, web developers can implement measures such as using frame-busting scripts, employing X-Frame-Options headers in HTTP responses, or using Content Security Policy (CSP) to restrict the allowed sources of content.
categories: [clickjacking, iframe]
---

![xss]({{ site.baseurl }}/images/featured-images/clickjacking.jpg)

Clickjacking is a type of web attack where an attacker tricks a user into unknowingly clicking on a malicious element on a website. This is done by overlaying the legitimate element with a transparent malicious element. The goal of clickjacking is to deceive the user into performing unintended actions, such as sharing confidential information, downloading malware, granting permissions, or making a purchase.

To protect against clickjacking attacks, web developers can implement measures such as using frame-busting scripts, employing X-Frame-Options headers in HTTP responses, or using Content Security Policy (CSP) to restrict the allowed sources of content.

In this post, I aim to document my findings and observations while performing a SEED lab.

<br>

### Copy the benign website

In a clickjacking attack, the attacker's aim is to mimic the benign website as much as possible so that the victim cannot really tell that he or she is on a malicious website. One of the ways an attacker does this is through an iframe.

An iframe (inline frame) is an HTML element that is used for embedding another HTML document within the current HTML document. Web pages use iframes to include external content such as videos, maps, social media feeds, advertisements, or any other web content without having to write the code into their own HTML structure. The src attribute of the iframe specifies the website to be embedded and loaded into the iframe when the code is executed.

This task involves setting up a website `www.cjlab-attacker.com` to look like `www.cjlab.com` using an iframe. To achieve this, I do the following:

- add an iframe to `www.cjlab-attacker.com` by adding the below code to the website index page.

  `<iframe src="http://www.cjlab.com"></iframe>`
 
- modify the webpage CSS file to make the iframe cover the whole page by adding the below to the CSS file.

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
  ![task-1-a](https://github.com/iukadike/blog/assets/58455326/de3f37ba-db92-41cb-ba8c-511e3b1c8729)

  ***`www.cjlab-attacker.com`***
  ![task-1-b](https://github.com/iukadike/blog/assets/58455326/96e9835e-9b92-484f-8e7e-63df6e4cf9ea)

With the iframe inserted, the attacker's website, `www.cjlab-attacker.com`, looks like the benign website, `www.cjlab.com`.

<br>

### Position a button over the target area

With the website already cloned, the next step is to create a button that will reside in the iframe.

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

![task-2-a](https://github.com/iukadike/blog/assets/58455326/8e5af2d7-30a6-4450-a37f-986069451ade)


However, the malicious button needs to cover the target area (in this case, "Explore Menu") and needs to be invisible. To achieve this, I do the following:

- modify the webpage CSS file to make the button cover the target area by adding the below to the CSS file.

  ```css
  button{
      ... /* existing code snippet. */
      margin: 8em 0px 0px 1em; /* margin: top right bottom left */
  }
  ```

  ![task-2-b](https://github.com/iukadike/blog/assets/58455326/b84c760a-dd60-4476-a19f-220474c2074d)


- modify the webpage CSS file to make the button transparent by adding the below to the CSS file.

  ```css
  button{
      ... /* existing code snippet. */
      color: rgba(0,0,0,0.0);  /* font color with full transparency*/
      background-color: rgba(0,0,0,0.0);  /* button's background color with full transparency */
  }
  ```

  ![task-2-c](https://github.com/iukadike/blog/assets/58455326/dc13df29-4b3c-4047-b738-70c717a65c8e)


Comparing the appearance of the attacker's website, `www.cjlab-attacker.com`, to the benign website, `www.cjlab.com`, we can see that there is no surface evidence that a functioning clickjacking attack is present on the website.

When the victim clicks the "Explore Menu" button on the attacker's website, the victim is redirected to a page different from the action that is expected from the real `www.cjlab.com` website.

![task-2-d](https://github.com/iukadike/blog/assets/58455326/27c9eac4-bcc8-4361-b2a5-15340d02ab40)


Consider this scenario. An attacker creates a fake webpage that mimics a real website. J. Doe, a victim, unknownly clicks the malicious link on the fake webpage, thinking he is on the real webpage. As a result of clicking on that link, pornographic contents and propaganda get posted to J. Doe's social media page. Now, this can lead to not just undesirable consequences for the victim, but very serious consequences.

This is to show how serious clickjacking, if not prevented, can be.

<br>

### Frame Busting

Frame busting, also known as frame blocking, is a security measure used to protect against clickjacking by preventing a webpage from being displayed within a frame on another website.

When a website uses frame busting, it ensures that the webpage is displayed as intended, and website owners can safeguard their content and user data and ensure a more secure browsing experience for their visitors.

There are different methods for implementing frame busting. Some of them include:

- JavaScript: this involves using a script that checks whether the website is being displayed within a frame. If it detects that it is embedded within a frame, the script instructs the browser to break out of the frame and load the page independently in the main browser window. Also, there are existing JavaScript libraries that have been specifically designed for frame busting, i.e., the Frame Buster library. These Javascript libraries can provide a ready-to-use solution for preventing framing.

- X-Frame-Options HTTP header: this involves setting the "X-Frame-Options" HTTP header with a value of "DENY" or "SAMEORIGIN". "DENY" ensures the webpage cannot be embedded in an iframe by any other site, while "SAMEORIGIN" allows embedding in an iframe by pages from the same origin.

- Content Security Policy (CSP): this involves implementing a CSP with the "frame-ancestors" directive, which specifies what origins are allowed to frame the website.

- Server-side checks: this involves checking the "Referer" or "Origin" header of incoming requests on the server-side to identify if a website is being framed or not.

___

This task involves making changes to `www.cjlab.com`s index file to include Javascript code that will perform frame busting. To achieve this, I add the following Javascript code to the index page of `www.cjlab.com`:

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

As seen from the screenshot below, when I navigate to the attacker's `www.cjlab-attacker.com`, rather than `www.cjlab.com` loading in an iframe, the website breaks out of the frame and loads independently. This means when the "Explore Menu" button is clicked, nothing malicious happens but the expected button action happens.

![task-3-a](https://github.com/iukadike/blog/assets/58455326/7ae90712-8727-4e6d-aeea-00cbded40879)


<br>

### Attacker Countermeasure against Frame-Busting Script

This task involves exploring how an attacker can create a workaround for frontend clickjacking defenses like frame-busting. This task makes use of adding the sandbox attribute to the malicious iframe to defeat frame busting.

Sandboxing is a technique that creates a virtual "box" area where application codes can run in isolation without being able to access other parts of the system. In the case of an iframe, by setting the sandbox attribute, we can effectively tell the browser to run the iframe in a sandbox and isolate it from accessing other actions of the web browser. Thus, the frame-busting script is rendered ineffective as it will not be able to create any action outside of the sandbox.

To achieve this, I make the following adjustment to the iframe tag in the HTML code:

`<iframe src="http://www.cjlab.com" sandbox=""></iframe>`

As seen from the screenshots below, when I navigate to `www.cjlab-attacker.com` after updating the iframe to use the sandbox attribute, the attack works. The frame-busting script is rendered ineffective. Thus, when the "Explore Menu" is clicked, the user is redirected to the malicious website to show that the attack is indeed working.

![task-4-a](https://github.com/iukadike/blog/assets/58455326/a512250f-2a21-42bd-9b71-c7f2ee911749)


![task-4-b](https://github.com/iukadike/blog/assets/58455326/8872daf0-6a7c-4dba-a5cd-72b82d2a1d87)


<br>

### The Ultimate Bust

From the previous task, it is evident that front-end defenses can be directly circumvented by the attacker implementing other front-end settings. This is where
back-end (server-side) defenses come into play.

Special HTTP headers have been created that specify to browsers the circumstances under which a website’s content should or should not be loaded. One such header is called "X-Frame-Options", and a newer, more popular one is called "Content-Security-Policy".

X-Frame-Options specifies whether a web page can be displayed inside a frame or not. It can have either of the following three values:

- DENY: This value instructs the browser to never allow the page to be displayed inside a frame.
  `X-Frame-Options: "DENY"`

- SAMEORIGIN: This value allows the page to be displayed inside a frame only if the frame is from the same origin as the page.
  `X-Frame-Options: "SAMEORIGIN"`

- ALLOW-FROM URI: This value allows the page to be displayed inside a frame if the frame is from the specified URI.
  `X-Frame-Options: "ALLOW-FROM https://example.com"`

The CSP directive that helps prevent clickjacking is "frame-ancestors". This directive specifies the valid sources that may embed a page in a frame. The frame-ancestors values could include any of the following:

- 'self': This allows the page to be embedded only on the same origin as the page itself.

- 'none': This disallows any embedding of the page in a frame from any website.

- Specific URLs: This allows embedding of the page in a frame from the specific sources.

- 'blob:': This allows embedding from blob URIs.

- '*.example.com': This allows embedding from any subdomain of `example.com`.

- 'https://*.example.com': This allows embedding from any subdomain of example.com using HTTPS.


This task involves implementing server-side defenses to guard against clickjacking by modifying `www.cjlab.com`'s response headers. To achieve this, I would need to edit the Apache configuration file for `www.cjlab.com` and add the following:

```
<VirtualHost *:80>
    DocumentRoot /var/www/defender
    ServerName www.cjlab.com
    Header set X-Frame-Options "DENY"
    Header set Content-Security-Policy " \
             frame-ancestors 'none'; \
           "
</VirtualHost>
```

When I navigated to `www.cjlab-attacker.com` after adding the X-Frame-Options response header to `www.cjlab.com`, the web browser refused to display `www.cjlab.com` because it was embedded in a frame.

![task-5-a](https://github.com/iukadike/blog/assets/58455326/6d99e263-dabb-4357-94e8-8db126ae388c)


When I navigated to `www.cjlab-attacker.com` after adding the CSP response header to `www.cjlab.com`, the web browser also refused to display `www.cjlab.com` because it was embedded in a frame.

![task-5-a](https://github.com/iukadike/blog/assets/58455326/6d99e263-dabb-4357-94e8-8db126ae388c)

<br>

In conclusion, clickjacking works by tricking victims into clicking on invisible buttons on a website while they actually intend to click on something else. The consequences of clickjacking can vary depending on the attacker's intentions, but they can be very serious. To prevent clickjacking attacks, website developers can take certain precautions, such as using the X-Frame-Options HTTP response header and the CSP "frame-ancestors" directive, to prevent their website from being embedded in frames on other domains.

The [Open Web Application Security Project (OWASP) page on clickjacking](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html) explores various methods of clickjacking, defenses against those methods, and how effective the defenses are.

Thanks for reading.
