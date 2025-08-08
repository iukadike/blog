---
layout: post
title: MRCI Learning Update - Part 3
categories: mrci
---

This post builds on my previous post [MRCI Learning Update - Part 2](https://iukadike.github.io/blog/mcri-collection-2/) and continues to highlight some of the labs I worked on and the lessons learned during my remote internship with Mossé Cyber Security Institute.


### Lab: Write a PS script that installs an insecure Windows Service

Some of the characteristics that make a Windows service insecure are:

- Outdated software
- Improper permissions
- Misconfiguration

To gain an understanding of what makes a Windows service vulnerable, how a vulnerable Windows service may be exploited, and how to secure Windows services, I wrote a PowerShell script that created an insecure Windows service and installed it on a machine. I then proceeded to exploit the vulnerable Windows service.

![1](https://github.com/user-attachments/assets/ae1b021f-368d-4e74-a96d-8fe1efa031c0)


### Lab: Write a PS script that enables the AlwaysInstallElevated registry key

Typically, when a user installs a Windows MSI package, the installer requires that the user have administrative privileges. However, if the "AlwaysInstallElevated" registry value is set to "1" (enabled), any user, even those with limited privileges, can install MSI packages with system-level privileges. Attackers could employ social engineering or other means to trick unsuspecting users into running their malicious MSI packages.

To gain an understanding of the effect of the AlwaysInstallElevated vulnerability in Microsoft Windows and the potential risks associated with it, I wrote a PowerShell script to enable the registry key and leveraged PowerUp.ps1 to escalate privileges.

![2](https://github.com/user-attachments/assets/d17bb322-c2bc-4534-9200-d3db2e26a7fc)


### Lab: Write an application vulnerable to Arbitrary Command Execution

Since exploiting a command execution vulnerability can lead to severe consequences, such as unauthorized access to sensitive data and complete control of the web server, application developers and security professionals need to understand how these vulnerabilities can be exploited.

To comprehend the risks of arbitrary command execution vulnerabilities and the significance of input validation and sanitization in web applications, I created a deliberately vulnerable web application that is susceptible to arbitrary command execution and exploited it.

![3](https://github.com/user-attachments/assets/52ef40f5-a144-4ab1-b0bd-5a3d0dab6322)


### Lab: Execute arbitrary commands on a server via SQL injection vulnerability

The xp_cmdshell stored procedure available in Microsoft SQL Server allows users to run operating system commands from within the SQL Server environment.

Though enabling the xp_cmdshell stored procedure provides benefits like:

- Backing up databases to external drives.
- Managing server files and folders.
- Creating and managing system jobs.
- Performing system administration tasks.
- Running custom tools and scripts.

It also poses risks, such as:

- Attackers can use it to execute malicious code.
- Attackers can use it to access or modify sensitive data.
- Attackers can use it to gain control of the server.
- Unintentionally delete or corrupt data.
- Unintentionally modify system settings.

Due to the security risks posed, xp_cmdshell is disabled by default in new SQL Server installations. It should only be enabled when absolutely necessary, and then disabled again as soon as possible

![4](https://github.com/user-attachments/assets/0585602e-23f4-4907-a972-fdf5cb5326e5)


### Lab: Write a tool to brute-force authentication pages

In web app security testing, brute force tools enable web app testers to pinpoint potential vulnerabilities, including weak passwords, within a system. Brute-force tools provide a means to assess the robustness of passwords and the existing security measures of a system. By employing a brute force tool, testers can rapidly uncover vulnerabilities that might otherwise remain undetected.

To gain practice, I hosted a local web app that could authenticate users and wrote a custom brute force tool in Python that could handle both vertical and horizontal brute force to uncover vulnerabilities in login pages.

![5](https://github.com/user-attachments/assets/b9a7d6cd-4cb7-4db5-84a0-67f74a29c4ef)


Thanks for reading.









