# Web App, Linux, Windows Pen Test

## Description  

This project focuses on conducting a Capture The Flag (CTF) penetration test for the fictional company Rekall, targeting their web application, Linux servers, and Windows servers. The objective is to exploit vulnerabilities across all three platforms to expose current security weaknesses and provide effective mitigations. This approach aims to enhance the overall security posture of Rekall while ensuring compliance with established security standards.

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

## Rekall Web Application Attack

During the assessment of a Rekall's web application, multiple vulnerabilities were identified across different locations, revealing various security weaknesses. Below are the details of these findings:

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


---

## Rekall Linux Server Attack

During the security assessment of Rekall's Linux infrastructure, several vulnerabilities were identified. These findings expose risks that could be exploited by attackers to gain unauthorized access, escalate privileges, or retrieve sensitive information. Below are the details of these findings:

### Open Source Exposed Data

- **Domain WHOIS Information**  
  - **Discovery:** Publicly accessible domain information revealed sensitive details.  
  - **Investigation Tool:** Domain Dossier at `centralops.net`.

- **Subdomain Enumeration**  
  - **Discovery:** Certificate transparency logs exposed additional subdomains.
  - **Investigation Tool:** `crt.sh` search for `totalrekall.xyz`.

---

### Network Reconnaissance

- **Host Discovery**  
  - **Scan Results:** A network scan revealed active hosts within the `192.168.13.0/24` subnet.  
  - **Key Finding:** Five active hosts were identified excluding the scanning machine.

- **Service Enumeration**  
  - **Vulnerable Host Identified:** An aggressive scan indicated that `192.168.13.13` runs **Drupal**, making it a potential target.

---

### Vulnerability Exploitation

#### Apache Struts Vulnerability (CVE-2017-5638)

- **Affected Host:** `192.168.13.12`
- **Discovery Method:** Nessus scan detected a critical vulnerability.
- **Exploit:** Leveraging Metasploit's `struts2_content_type_ognl` exploit to gain access.
- **Post-Exploitation:** Retrieved sensitive files containing a potential flag.

#### Apache Tomcat RCE (CVE-2017-12617)

- **Affected Host:** `192.168.13.10`
- **Exploitation Method:** Metasploit's `tomcat_jsp_upload_bypass` module was used to gain a Meterpreter shell.
- **Privilege Escalation:** Retrieved root-level sensitive information.

#### Shellshock Exploit

- **Affected Host:** `192.168.13.11`
- **Exploitation Method:** Apache's CGI module was vulnerable to Shellshock.
- **Exploitation Steps:**
  - Leveraged `apache_mod_cgi_bash_env_exec` module.
  - Gained shell access and extracted critical system files.

---

### Additional Security Weaknesses

- **Drupal Exploit (CVE-2019-6340)**
  - **Host:** `192.168.13.13`
  - **Exploit:** Used Metasploit's `drupal_restws_unserialize` module.
  - **Result:** Gained access to the server with the `www-data` user.

- **Privilege Escalation via Sudo Misconfiguration (CVE-2019-14287)**
  - **Host:** `192.168.13.14`
  - **Misconfiguration:** WHOIS data suggested an `sshuser` account with weak credentials.
  - **Exploit:** Used `sudo -u#-1` to escalate privileges and retrieve sensitive data.


---

## Rekall Windows Server Attack

During the security assessment of Rekall's Windows Server infrastructure, several vulnerabilities were identified. These findings present risks that could be exploited by attackers to gain unauthorized access, escalate privileges, or retrieve sensitive information. Below are the details of these findings:

## Enumeration and Information Gathering

### GitHub Repository Discovery
- A public repository related to Rekall was identified on GitHub.
- Searching within the repository led to the `xampp.users` page, revealing stored credentials.
- The credentials were hashed using `$apr1$` format, indicating they could be cracked using John the Ripper.

### Network Scanning
- A subnet scan (`172.22.117.0/24`) revealed two machines:
  - `Win10 @ 172.22.117.20`
  - `Server2019 @ 172.22.117.10`
- Further scans identified open ports, including HTTP, FTP, SMTP, and POP3 services.

## Exploitation

### Web Authentication Bypass
- Visiting `http://172.22.117.20` prompted authentication.
- Using the cracked credentials (`trivera : Tanya4life`), access was granted to retrieve sensitive files.

### FTP Anonymous Access
- FTP access was enabled for anonymous users.
- Using FTP commands, files were retrieved, including a flag stored in `flag3.txt`.

### SLMail Exploitation
- SLMail service was running on port 110.
- Using Metasploit, a known exploit was applied, leading to a Meterpreter session.
- Once inside, directory listing revealed `flag4.txt`.

### Scheduled Task Exploitation
- Scheduled tasks were enumerated using system commands.
- A flagged task contained critical information when queried.

### Credential Dumping
- Post-exploitation tools like `kiwi` were used to extract user credentials.
- Cached credentials of an administrator were identified and cracked.
- The retrieved credentials were leveraged to escalate access to the `Server2019` machine.

### Privilege Escalation
- `PsExec` was used to obtain SYSTEM privileges on `Server2019`.
- A DCSync attack was performed to retrieve the NTLM password hash of the administrator.
