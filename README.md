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

### Reflected Cross-Site Scripting (XSS)

- **Welcome.php:** Found an XSS vulnerability that can be triggered with the payload `<script>alert("test")</script>`.
- **Memory-Planner.php (first field):** Identified an advanced XSS reflection where input validation removes "script," requiring a modified payload such as `<SCRIPscriptT>alert("test")</SCRIPscripTt>`.

### Stored Cross-Site Scripting (XSS)

- **comments.php:** Found a stored XSS vulnerability allowing persistent execution of JavaScript payloads.

### Sensitive Data Exposure

- **About-Rekall.php:** Exposed sensitive data within HTTP response headers, which can be accessed using Burp Suite or a cURL request:
  
  *(Use `curl -v [target URL]` to inspect headers.)*

- **Login.php (second field):** User credentials were embedded within the HTML source and could be revealed by inspecting the page.
- **robots.txt:** Contained sensitive data exposure by listing directories accessible without authentication.

### Local File Inclusion (LFI)

- **Memory-Planner.php (second field):** LFI vulnerability allows arbitrary file uploads.
- **Memory-Planner.php (third field):** An advanced LFI vulnerability was found where the input validation checks for `.jpg`. Bypassing it requires naming a script `script.jpg.php`.

### SQL Injection

- **Login.php (first field):** SQL injection was exploitable using payloads like:
  
  *(Use `ok' or 1=1--` to bypass authentication.)*

### Command Injection

- **networking.php (first field):** The application was vulnerable to command injection using:
  
  *(Modify the URL or input field to append `&& cat vendors.txt`.)*

- **networking.php (second field):** A more advanced form of command injection required modifying the payload to:
  
  *(Use `| cat vendors.txt` instead of `&&` or `;`.)*

### Brute Force Attack

- **Login.php (second field):** Using command injection vulnerabilities, the `/etc/passwd` file revealed a valid username and password combination.

### PHP Injection

- **souvenirs.php:** This hidden page was discovered through `robots.txt`, and a PHP injection vulnerability was exploited using:
  
  *(Modify the URL to `?message=""; system('cat /etc/passwd')`.)*

### Session Management Weakness

- **admin_legal_data.php:** Session IDs were predictable, and testing different values with Burp Suite revealed a valid session at `?admin=87`.

### Directory Traversal

- **Disclaimer.php:** The page hinted at older disclaimers, and directory traversal was used to access previous versions by modifying the URL:
  
  *(Modify `?page=old_disclaimers/disclaimer_1.txt` to access previous versions.)*


![Screenshot 2025-02-12 at 3 17 55 PM](https://github.com/user-attachments/assets/d45623e3-ba1b-4ea7-a127-6f97e9e146f1)
![Screenshot 2025-02-12 at 3 18 29 PM](https://github.com/user-attachments/assets/4d0514b7-c6d6-4f20-bc89-b5aed7b199ef)
![Screenshot 2025-02-12 at 3 18 55 PM](https://github.com/user-attachments/assets/1bab31cd-6573-44b2-9a97-ed98393f8860)





These findings illustrate significant security weaknesses that require immediate remediation to prevent exploitation.
    

