---
layout: post
title: MRCI Learning Update - Part 2
categories: lab setup
---

This post builds on my previous post [MRCI Learning Update - Part 1](https://iukadike.github.io/blog/mcri-collection-1/) and continues to highlight some of the labs I worked on and the lessons learned during my remote internship with Mossé Cyber Security Institute.


### Lab: Write a PS script that detects whether a machine has more than 1 local administrator

A characteristic of a local administrator account is that it has elevated privileges, allowing the user to modify system settings, install software, and access sensitive data. Therefore, having multiple local administrator accounts means more people with such privileges, increasing the risk of unauthorized access or misuse of administrative rights.

As this directly leads to an Increased attack surface, as each administrator account can be a potential entry point for attackers trying to gain unauthorized access to a corporate network, I wrote a PowerShell script to detect whether a machine has more than 1 local administrator account and alert the analyst running the script.

![1](https://github.com/user-attachments/assets/6e47f14a-153a-437f-bf7e-249db55d409f)


### Lab: Write a PS script to list missing security patches

Security patches are critical to protecting corporate networks and infrastructure from cyber threats. Attackers often exploit known vulnerabilities in software to gain access to systems, and security patches can help close these vulnerabilities and prevent attacks.

To audit local and remote machines for missing patches, I wrote a PowerShell script that queried the system for patch information.

![2](https://github.com/user-attachments/assets/7480477d-83f0-446b-934b-6b970aa03f0c)


### Lab: Write Yara rules

Yara rules are a valuable tool for threat hunters. Security analysts can create rules to identify specific families of malware threats. These rules can be used to scan for malware on systems, identify malicious files, and track down malware infections. Threat hunters can use Yara rules to quickly and easily identify potential threats.

In cybersecurity, collaboration and clear communication are essential. Well-documented YARA rules ensure that team members and stakeholders understand the rule’s purpose and functionality. Yara rules should include metadata such as author name, description, rule version number, and reference URLs.

To get some practice under my belt, I wrote the following Yara rules:

- A sample Yara rule that is properly documented.
- A YARA rule that finds Windows Portable Executables (PEs) less than 500KB.
- A YARA rule that searches for files containing two unique strings.
- A YARA rule to catch the exploits targeting the vulnerabilities in the Telerik software.
- A YARA rule that can find binaries that have more than 3 URLs.
- A YARA rule that generically detects improperly signed Windows executables.
- A YARA rule that searches for strings using hex and wildcards.
- A YARA rule that detects suspicious Windows APIs.

![3](https://github.com/user-attachments/assets/5e003f81-3789-4505-8e7e-5a3b4d893bb6)
![4](https://github.com/user-attachments/assets/8ed7ca25-3e45-4201-81dd-97bb2071ec35)


### Lab: Threat Hunting

Threat hunting can help organizations gain valuable insights into their security posture and vulnerabilities, which can then be used to make informed decisions to strengthen their overall security. Threats can then be addressed before they cause damage to the organization.

To facilitate threat hunting, security professionals could make use of the following toolset.

- Python pandas is a tool that can be used to efficiently and effectively analyze large data sets. This can be used to identify potentially malicious or unauthorized activity in an organization's data. Patterns in the data that may indicate a threat can be identified and then further investigated by the security analyst. Python pandas can be used to analyze data from various sources, such as logs, network traffic, and endpoints. This makes it a valuable tool for identifying and responding to threats. 
- Yara, also known as the Blue Teamer’s Swiss army knife, can be used to create custom rules that can be used to scan for malware on systems, identify malicious files, and track down malware infections.

Apart from having toolsets, it is crucial to have datasets.

- Goodware dataset (a dataset that is known to be clean and does not contain any malicious files, scripts, or payloads) to use as a point of comparison against other datasets during threat-hunting activities. This will help to identify potential malicious activity and avoid false positives.
- Malware datasets to help identify new malware families and variants. These datasets allow researchers to study malware and develop defenses against it. 

To get some practice under my belt, I completed the following Yara tasks:

- Created a Python virtual environment using poetry where I installed pyarrow (a library for working with Parquet files), pandas (a library for data analysis), NumPy (a library for scientific computing), and JupyterLab (a web-based interactive development environment) to work on threat datasets packaged in the Parquet file format.
- Installed Yara and a hex editor. I also obtained a 15GB+ goodware dataset that I can use to test my Yara rules to ensure that they do not produce false positives.
- Obtained a 5GB+ malware dataset for security research. This dataset includes a broad range of malware samples, such as PDF, exe, js, dll, etc.

![5](https://github.com/user-attachments/assets/1fc38604-d2a6-4f4f-a050-3137ef081f40)
![6](https://github.com/user-attachments/assets/4fba2016-39b9-4880-ba07-c8b36579e3d7)


Thanks for reading.
