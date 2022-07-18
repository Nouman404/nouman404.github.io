---
title: Notes | Web Applications
author: Zeropio
date: 2022-07-18
categories: [Notes, Web]
tags: [enumeration]
permalink: /notes/web/web-applications
---

# Errors

The most common mistakes creating web applications are:
1. Permitting Invalid Data to Enter the Database
2. Focusing on the System as a Whole
3. Establishing Personally Developed Security Methods
4. Treating Security to be Your Last Step
5. Developing Plain Text Password Storage
6. Creating Weak Passwords
7. Storing Unencrypted Data in the Database
8. Depending Excessively on the Client Side
9. Being Too Optimistic
10. Permitting Variables via the URL Path Name
11. Trusting third-party code
12. Hard-coding backdoor accounts
13. Unverified SQL injections
14. Remote file inclusions
15. Insecure data handling
16. Failing to encrypt data properly
17. Not using a secure cryptographic system
18. Ignoring layer 8
19. Review user actions
20. Web Application Firewall misconfigurations

This lead to the OWASP Top 10:
1. Injection
2. Broken Authentication
3. Sensitive Data Exposure
4. XML External Entities (XXE)
5. Broken Access Control
6. Security Misconfiguration
7. Cross-Site Scripting (XSS)
8. Insecure Deserialization
9. Using Components with Known Vulnerabilities
10. Insufficient Logging & Monitoring

# URL Encoding

Each page use a charset. For example, the URL uses ASCII enconding. This could lead to change in the text to get exploits. These are some examples:

| **Character**   | **Encoding**    |
|--------------- | --------------- |
| `space` | %20 |
| `!` |	%21 |
| `"` |	%22 | 
| `#` |	%23 |
| `$` |	%24 | 
| `%` |	%25 |
| `&` |	%26 |
| `'` |	%27 |
| `(` |	%28 |
| `)` |	%29 |

[Here](https://www.w3schools.com/tags/ref_urlencode.ASP) are a full encoding table.








