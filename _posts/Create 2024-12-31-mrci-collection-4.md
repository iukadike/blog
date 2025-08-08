---
layout: post
title: MRCI Learning Update - Part 4
categories: lab setup
---

This post builds on my previous post [MRCI Learning Update - Part 3](https://iukadike.github.io/blog/mrci-collection-3/) and continues to highlight some of the labs I worked on and the lessons learned during my remote internship with Mossé Cyber Security Institute.


### Lab: Write a web application that correctly utilizes the secure cookie flag

To ensure the security of user data, cookies must be transmitted solely over HTTPS connections by setting the secure flag. Without the secure flag, cookies are transmitted over HTTP and HTTPS connections. This poses a significant security risk, allowing an attacker on an unsecured network to potentially intercept cookie data sent over plain HTTP. This could lead to the attacker impersonating the user by sending the stolen cookie back to the server.

To understand the impact of the secure cookie flag, I deployed a web application over SSL that allows users to log in, generates a session token for the user, and stores the session token in a secure cookie.

![1](https://github.com/user-attachments/assets/30230067-522a-4ca8-a784-857b018e5f7c)


### Lab: Write a web application that correctly utilizes the HTTP-only Cookie flag

When a cookie has the HTTP-Only flag set, it becomes inaccessible by client-side scripting languages like JavaScript within the user's browser. If a website sets a cookie without the HttpOnly flag and the cookie contains sensitive information, a potential XSS vulnerability could allow the attacker's script to access and steal the cookie data.

HTTP-Only cookies should be used in conjunction with the secure flag to provide additional protection.

To understand the impact of the HTTP-Only cookie flag, I deployed a local web server that allows users to log in, generate a session token for the user, and store the session token in a secure cookie.

![2](https://github.com/user-attachments/assets/ab659807-9d7c-4df4-a916-ff58232030c1)


### Lab: Write a web application that automatically logs out users after 5 minutes of inactivity

When a user visits a web application, the server creates a user session for that particular visit. If an idle session is kept for long, it can lead to security risks, such as session token reuse by adversaries or unauthorized access if the user's device is compromised.

To explore this concept, I deployed a web application that automatically logs out users after 5 minutes of inactivity.

![3](https://github.com/user-attachments/assets/ed35e164-3cbd-4ee5-a2be-87fc30f8ef7f)


### Lab: Write a web application that prevents clickjacking

The X-Frame-Options (X-FO) is a security header specifically designed to mitigate clickjacking attacks. The X-Frame-Options HTTP header is an HTTP header that a website can send in its response that instructs compatible web browsers on how to handle the content of that page when it is loaded inside a frame.

It can be set to "DENY" or "SAMEORIGIN", or "ALLOW-FROM", and tells the browser whether or not the page can be loaded in a frame by other pages.

- DENY instructs the browser to never display the content of that page inside any frame.
- SAMEORIGIN  allows the page to be loaded inside a frame, but only if the frame originates from the same domain as the page itself.
- ALLOW-FROM [url]: allows the page to be loaded inside a frame only if the frame originates from the specified URL.

To explore the dangers of clickjacking and its prevention, I developed a web application that sets the X-Frame-Options to prevent clickjacking attacks.

![4](https://github.com/user-attachments/assets/7b4f940c-c03d-40d5-a382-bbe7e2e05e6f)


Thanks for reading.
