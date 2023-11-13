---
layout: post
title: Cybersecurity Lab Setup
categories: lab setup
---

As a cybersecurity student and aspiring cybersecurity professional, it is essential to continually enhance my cybersecurity abilities. This is why I chose to enroll in Mosse Cyber Security Institute and take their remote internship course (MRCI).

While working as a cybersecurity professional, the following needs are bound to arise:

- the need to document my work as a video recording
- the need to prepare a professional document.
- the need to test security tools
- the need to perform analysis in a sandboxed environment.

One of the very first topics covered in MRCI is setting up a cybersecurity lab that would be used for the remaining modules.


### Lab Setup: Screen Recording

Recording my screen is essential because it will allow me to record and document cybersecurity exploits for reporting purposes. In this lab, I set up OBS Studio to record my entire screen and made sure the capture was done at a minimum resolution of 720p.


### Lab Setup: Deploy a Virtual Machine

A virtual lab begins with a virtual machine. Virtual machines are used to create isolated and virtualized environments for a variety of purposes, such as software testing, malware analysis, and cybersecurity training. VMs are simple to set up and can be spun up quickly once they have been initially configured. Some pre-built images can be used. In this lab, I installed Virtual Box and set up two virtual environments: a Kali Linux VM and a Windows 10 VM.


### Lab Setup: GVM

Vulnerability scans are used to identify security risks in software and infrastructure. They can find misconfigured systems and recommend ways to mitigate or remove the risks. Vulnerability scans are performed using automated tools such as Nessus and OpenVAS (now GVM - Greenbone Vulnerability Management).

GVM is a widely used vulnerability scanning toolkit that helps cybersecurity professionals identify and address known vulnerabilities in systems. Traditionally, manual installation of GVM can be time-consuming and complex. However, using a Docker container streamlines the installation process, making it faster and more efficient.

In this lab, I installed Docker, pulled the GVM community edition Docker containers using the supplied docker-compose file, started the containers, and performed a scan on a Windows XP host. The scan identified several vulnerabilities, including a remote code execution vulnerability in the Windows XP operating system.


### Lab Setup: Create a template for a professional document

Report writing is a critical skill for any cybersecurity professional. Reports must be accurate and comprehensive, yet simple enough for everyone involved to quickly grasp the situation. Cybersecurity professionals typically write malware analysis reports, digital forensics reports, penetration testing reports, "policies, procedures, and guides", "standards and baselines", etc.

Report writing is a skill that improves with practice. In this lab, I am taking my first step towards writing a professional document by creating a template report.


#### Some problems I faced

When recording my screen, OBS uses CPU resources to encode the video. Often, I will have at least two VMs running while also using OBS to capture my screen. One issue was how to choose the best settings in OBS Studio to produce lag-free, high-quality screen recordings while using moderate CPU resources. After some trial and error, I was able to find a setting that worked well with my system specifications.

When setting up virtual machines (VMs), they will typically share the host's resources, such as disk space, RAM, and CPU. Many of these VMs have minimum specifications that must be met for them to function. Because my PC's specifications are not very high, I try to run at most two VMs at their base specifications while I plan to upgrade my PC.

After starting the GVM docker containers, I tried to perform a scan immediately but encountered many errors. After doing some research, I realized that GVM takes some time to initialize and sync data that will be used for the assessments. The time frame varies depending on system specifications, but the progress can be tracked by viewing the logs it generates.


|     |     |
| --- | --- |
| ![Lap Setup: Screen Recording](https://github.com/iukadike/blog/assets/58455326/d284f798-6ac1-49fc-aec7-ef3e34607af4) | ![Lab Setup: Deploy a Virtual Machine in Virtualbox](https://github.com/iukadike/blog/assets/58455326/5c435f61-9c8f-490a-ac96-2ac26e83d623) |
| ![Lab Setup: OpenVAS](https://github.com/iukadike/blog/assets/58455326/3f05cf0a-e312-423f-8547-fa3a1720b524) | ![Create a template for a professional document](https://github.com/iukadike/blog/assets/58455326/eae9a2ba-cac2-4938-a995-921c7cc28bdf) |
