---
layout: post
title: MRCI Learning Update - Part 1
categories: mrci
---

My remote cybersecurity internship was an immersive experience that pushed me to develop my capacity. Throughout the experience, I had to adapt and learn new tools. In this post, I’ll highlight some of the labs I worked on and the lessons learned.


### Lab: Use SSLScan to access the SSL configuration settings of HTTPS websites

SSL information can be used by both attackers and defenders. Attackers can use information gathered from examining SSL information to exploit vulnerabilities in weak and outdated SSL versions. Defenders can use information gathered from examining SSL information to ensure that their infrastructures are securely configured.

After scanning six HTTPS websites with SSLScan, I received some interesting results. All of the websites supported a variety of cipher suites, with some supporting more than others. None of them supported an outdated cipher suite, and they all supported at least one weak cipher suite, which I believe is for backward compatibility. However, they always preferred the strongest cipher suite.

![1](https://github.com/user-attachments/assets/ba6e0341-5b7a-4459-992e-3c7936b26eb8)


### Lab: Perform a port scan using Nmap

It is essential to have knowledge of the open ports and services in an infrastructure to secure the system and mitigate potential vulnerabilities. One approach to determining which ports are open is to scan the network.

To practice port scanning using Nmap, I set up two virtual machines (VMs), one as the target and the other as the scanner. I then started the following services on the target VM while scanning for the services using the attacker VM:

- apache2 (TCP 80)
- ssh (TCP 22)
- snmp (UDP 161)


### Lab: Perform a vulnerability scan with OpenVAS

Vulnerability scans are important because they can help identify security risks in a system before they can be exploited. Vulnerability scans can be used to identify a wide range of security risks, such as:

- open ports
- misconfigured systems
- unpatched vulnerabilities

The findings were quite intriguing because each operating system had its own set of vulnerabilities, some serious and others not so serious, right out of the box. This demonstrates why operating systems should be hardened before being deployed.

![2](https://github.com/user-attachments/assets/3229f56c-fcfd-4893-b5fd-c31b05403f3f)


### Lab: Bruteforce web directories and files using wfuzz

To address their security posture, organizations need to know what directories and files are visible to the public as part of a web security assessment. Automated tools such as dirb, ffuf, dirbuster, gobuster, and wfuzz can be used to discover hidden directories and files.

To hone my security assessment abilities, I used WFUZZ to conduct directory brute force attacks against DVWA to discover hidden web pages and folders within the web application. After the assessment, I learned that the results obtained from WFUZZ are only as good as the wordlist that is used.

![3](https://github.com/user-attachments/assets/9e1c0821-3a4b-4126-89d6-2e576b08000d)


### Lab: Perform DNS scans using Fierce

Mapping a network infrastructure is crucial because it allows cybersecurity professionals to identify potential entry points and weak spots that cyber attackers may exploit. This allows them to prioritize security measures and focus on securing these areas. Organizations can also implement appropriate access controls, such as firewall rules or network segmentation, to limit access to critical resources, reducing the attack surface and minimizing the potential impact of a breach.

Here, I used Fierce to discover subdomains of a domain. This information can be used to identify potential security risks, such as subdomains that are not properly secured or that are not supposed to be accessible to the public.

![4](https://github.com/user-attachments/assets/b308b2a3-b364-4a1b-a6a1-cf4e435ccc1d)


### Lab: Write a PS script that copies Sysmon to remote machines and installs it with a given configuration file

Sysmon can be set up with a configuration file to generate alerts when it detects suspicious activity. These alerts can be used to notify system administrators of potential threats.

To practice cyber defense, I write a PowerShell script that copies Sysmon to a remote machine and installs it with a supplied configuration file that catches the following events:

- unauthorized READ/WRITE access to lsass.exe
- the processes that run command-line execution arguments
- the drivers that are loaded
- the DLLs that process load

![5](https://github.com/user-attachments/assets/43be1088-f19f-49e3-8d21-4cf8c18901ca)


Thanks for reading.
