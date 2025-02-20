# Web Application, Linux, Windows Attack CTF

## Description  

This project focuses on improving the security, performance, and manageability of a Linux system by implementing various system hardening measures and best practices. The tasks are designed to address potential vulnerabilities, streamline system operations, and ensure compliance with security standards.

## Operating System  

- **Linux**
- **Windows**

## Skills Gained and Excercised

- **Web Application Penetration Testing**
   - Discovered and exploited vulnerabilities such as XSS (reflected and stored), SQL injection, command injection, and local file inclusion.
   - Used tools like Burp Suite and cURL to analyze and manipulate web traffic.
   - Gained access to sensitive information through improper input validation and weak session management.
 
- **Linux Server Exploitation**
   - Conducted network reconnaissance using Nmap and Nessus to identify open ports and vulnerabilities.
   - Exploited vulnerabilities such as Shellshock, Apache Struts RCE, and privilege escalation flaws.
   - Gained unauthorized access by leveraging weak credentials and SSH misconfigurations.
 
- **Windows Server Exploitation**
   - Identified open ports and running services through network scanning.
   - Exploited SLMail, scheduled tasks, and cached credentials for privilege escalation.
   - Used Metasploit modules to execute remote exploits and gain shell access.
   - Extracted user credentials and cracked password hashes using John the Ripper and Mimikatz.


---

## Web Application Attack

During the assessment of a web application, multiple vulnerabilities were identified across different locations, revealing various security weaknesses. Below are the details of these findings:

## Reflected Cross-Site Scripting (XSS)

- **Welcome.php**: Found an XSS vulnerability that can be triggered with the payload:
  ```html
  <script>alert("hi")</script>
  ```

- **Memory-Planner.php (first field)**: Identified an advanced XSS reflection where input validation removes "script," requiring a modified payload such as:
  ```html
  <SCRIPscriptT>alert("hi")</SCRIPscripTt>
  ```

## Stored Cross-Site Scripting (XSS)

- **comments.php**: Found a stored XSS vulnerability allowing persistent execution of JavaScript payloads.

## Sensitive Data Exposure

- **About-Rekall.php**: Exposed sensitive data within HTTP response headers, which can be accessed using Burp Suite or a cURL request:
  ```sh
  curl -v http://192.168.14.35/About-Rekall.php
  ```
- **Login.php (second field)**: User credentials were embedded within the HTML source and could be revealed by inspecting the page.
- **robots.txt**: Contained sensitive data exposure by listing directories accessible without authentication.

## Local File Inclusion (LFI)

- **Memory-Planner.php (second field)**: LFI vulnerability allows arbitrary file uploads.
- **Memory-Planner.php (third field)**: An advanced LFI vulnerability was found where the input validation checks for `.jpg`. Bypassing it requires naming a script:
  ```sh
  script.jpg.php
  ```

## SQL Injection

- **Login.php (first field)**: SQL injection was exploitable using payloads like:
  ```sql
  ok' or 1=1--
  ```

## Command Injection

- **networking.php (first field)**: The application was vulnerable to command injection using:
  ```sh
  www.welcometorecall.com && cat vendors.txt
  ```
- **networking.php (second field)**: A more advanced form of command injection required modifying the payload to:
  ```sh
  www.welcometorecall.com | cat vendors.txt
  ```

## Brute Force Attack

- **Login.php (second field)**: Using command injection vulnerabilities, the `/etc/passwd` file revealed a valid username and password combination.

## PHP Injection

- **souvenirs.php**: This hidden page was discovered through `robots.txt`, and a PHP injection vulnerability was exploited using:
  ```sh
  http://192.168.13.35/souvenirs.php?message=""; system('cat /etc/passwd')
  ```

## Session Management Weakness

- **admin_legal_data.php**: Session IDs were predictable, and testing different values with Burp Suite revealed a valid session at:
  ```sh
  ?admin=87
  ```

## Directory Traversal

- **Disclaimer.php**: The page hinted at older disclaimers, and directory traversal was used to access previous versions by modifying the URL:
  ```sh
  http://192.168.13.35/disclaimer.php?page=old_disclaimers/disclaimer_1.txt
  ```

These findings illustrate significant security weaknesses that require immediate remediation to prevent exploitation.
    

