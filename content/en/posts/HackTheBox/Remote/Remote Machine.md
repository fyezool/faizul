---
author: "faizul"
title: "Remote - Retired HackTheBox Machine"
date: 2020-09-02T12:00:06+09:00
description: "Remote Machine Writeup"
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
categories:
- writeup
---



Remote Machine

# Remote Machine

![da19d744b54b5b75faa15f8f90d41b6a.png](/images/htb/remote/1db791ea9b644c45b4fda076d48d83fa.png)
- ip 10.10.10.180


## Nmap Scan
```bash
21/tcp   open  ftp           Microsoft ftpd                                     
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)                          
| ftp-syst:                                                                     
|_  SYST: Windows_NT                                                            
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)            
|_http-title: Home - Acme Widgets                                               
111/tcp  open  rpcbind       2-4 (RPC #100000)                                  
| rpcinfo:                                                                      
|   program version    port/proto  service                                      
|   100000  2,3,4        111/tcp   rpcbind                                      
|   100000  2,3,4        111/tcp6  rpcbind                                      
|   100000  2,3,4        111/udp   rpcbind                                      
|   100000  2,3,4        111/udp6  rpcbind                                      
|   100003  2,3         2049/udp   nfs                                          
|   100003  2,3         2049/udp6  nfs                                          
|   100003  2,3,4       2049/tcp   nfs                                          
|   100003  2,3,4       2049/tcp6  nfs                                          
|   100005  1,2,3       2049/tcp   mountd                                    
|   100005  1,2,3       2049/tcp6  mountd                                       
|   100005  1,2,3       2049/udp   mountd                                       
|   100005  1,2,3       2049/udp6  mountd                                       
|   100021  1,2,3,4     2049/tcp   nlockmgr                                     
|   100021  1,2,3,4     2049/tcp6  nlockmgr                                     
|   100021  1,2,3,4     2049/udp   nlockmgr                                     
|   100021  1,2,3,4     2049/udp6  nlockmgr                                     
|   100024  1           2049/tcp   status                                       
|   100024  1           2049/tcp6  status                                       
|   100024  1           2049/udp   status                                       
|_  100024  1           2049/udp6  status                                       
135/tcp  open  msrpc         Microsoft Windows RPC                              
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn                      
445/tcp  open  microsoft-ds?
2049/tcp open  mountd        1-3 (RPC #100005)
```

How about some UDP port huh?

```bash
111/udp  open|filtered rpcbind     2-4 (RPC #100000)                            
| rpcinfo:                                                                      
|   program version    port/proto  service                                      
|   100000  2,3,4        111/tcp   rpcbind                                      
|   100000  2,3,4        111/tcp6  rpcbind                                      
|   100000  2,3,4        111/udp   rpcbind                                      
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
123/udp  open|filtered ntp
137/udp  open|filtered netbios-ns
138/udp  open|filtered netbios-dgm
500/udp  open|filtered isakmp
|_ike-version: ERROR: Script execution failed (use -d to debug)
2049/udp open          mountd      1-3 (RPC #100005)
4500/udp open|filtered nat-t-ike
5353/udp open|filtered zeroconf
5355/udp open|filtered llmnr
```
This UDP doesnt look promising. 


### Potential Attack Surface
- 21 - FTP is sweet juicy attacking surface
- 80 - Web pwning? yeahhh great
- 111 - me no speak MS language
- 2049 - I rarely see this, might be sweet juicy spot.


### Service recon
Nuff talk, lets enum all the open port. Get to know all available surface

#### FTP
![3deb4d7b96a8fb607e2acae646aa0acb.png](/images/htb/remote/f67f47620f544b9394be0cbcf2606c8b.png)

Crap, its nothing here. Lets move on to another service.

#### Web

Since its a windows machine, so automagically its an IIS/ASP web stack. For web, i usually do recon with gobuster. This will do dir brute against hosteb web service on this machine.

```bash
kali@fs0ci3ty $ gobuster dir -u http://10.10.10.180 -w /usr/share/wordlist/dirbuster/directory-list-2.3-medium.txt -o gobuster/root-enum
```

#### 2049 NFS
So, turn it this is Samba NFS. Juicy juice! Lets enum this and lets see what we got. 


![e66ef88377a065f4ae1d006b6cdcdc55.png](/images/htb/remote/ae6a87d4792144b9ae9ccf9484e4361a.png)


Lets enum this with nmap `nfs-ls` script

```bash
╰─λ sudo nmap -sCV --script nfs-ls nmap/nfs-ls-scan -iL ip              14:26:06                                                                                      
[sudo] password for kali:                                                                                                                                             
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-25 14:26 EDT                                                                                                       
Nmap scan report for remote.htb (10.10.10.180)                                                                                                                        
Host is up (0.34s latency).                                                                                                                                           
Not shown: 993 closed ports                                                                                                                                           
PORT     STATE SERVICE       VERSION                                                                                                                                  
21/tcp   open  ftp           Microsoft ftpd                                                                                                                           
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                                                  
111/tcp  open  rpcbind       2-4 (RPC #100000)                                                                                                                        
| nfs-ls: Volume /site_backups                                                                                                                                        
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute                                                                                                          
| PERMISSION  UID         GID         SIZE   TIME                 FILENAME                                                                                            
| rwx------   4294967294  4294967294  4096   2020-02-23T18:35:48  .                                                                                                   
| ??????????  ?           ?           ?      ?                    ..                                                                                                  
| rwx------   4294967294  4294967294  64     2020-02-20T17:16:39  App_Browsers                                                                                        
| rwx------   4294967294  4294967294  4096   2020-02-20T17:17:19  App_Data                                                                                            
| rwx------   4294967294  4294967294  4096   2020-02-20T17:16:40  App_Plugins      
| rwx------   4294967294  4294967294  8192   2020-02-20T17:16:42  Config           
| rwx------   4294967294  4294967294  64     2020-02-20T17:16:40  aspnet_client    
| rwx------   4294967294  4294967294  49152  2020-02-20T17:16:42  bin              
| rwx------   4294967294  4294967294  64     2020-02-20T17:16:42  css              
| rwx------   4294967294  4294967294  152    2018-11-01T17:06:44  default.aspx     
|_                                       
```
And we have one folder which is `site_backup`. To confirm this even more, lets do extend enum with `msf` and the script is `auxiliary/scanner/nfs/nfsmount`.


![93fb263ad98ce6c637f41421342c2052.png](/images/htb/remote/241d3c644d2a4d8997dc5a11c725cde8.png)

Enought with enum, lets mount this to our attacking machine machine. First thing im gonna do is to change my `/etc/hosts` and add `10.10.10.180 remote.htb`. 

Now, mount the `site_backup` with command `sudo mount -t nfs -o vers=2 remote.htb:site_backups $PWD/nfs -o nolock`

From here, cd to the `nfs` folder and crawl to get more info in order to get the initial fothold later. 

![58f01f8660a857fabf9616f476e928a8.png](/images/htb/remote/4bd125ad2f814bfeb16c4a57c52ec2bc.png)

Since this is Umbraco CMS, an Open Source .NET CMS. It is wise to read the docs. I straight away look for database and got this. 

![afec5e31111150653ca8e3cfac92ea10.png](/images/htb/remote/0ade57c8611e42f7a8efc2c1dbdec089.png)

According to Umbraco docs, it wil create `mdf` file if there is SQL Server installed on the machine and will create `sdf` file othrwise. Since there are no SQL server appearance during scan, lets find sdf file straightaway. 


![7777fe82f7b43c496d9c446c2542e348.png](/images/htb/remote/5526ecac4fe94bc49b3bb9e941f4bf62.png)

In AppData folder, there is Umbraco.sdf file. Using `strings` command, we can get to take a look what information stored inside. 

![5a6e65eaec3024defa909427bb194391.png](/images/htb/remote/0fad523d5f8a4bb58f89f95fb7aa8495.png)

We found the admin password hash. For this, we can crack the hash using hashcat or we can use crackstation for faster speed.


![eb55054b63e72ec6f0bdbff5dbd77064.png](/images/htb/remote/54d92b999ba0402dbed8f2aead9ebcd5.png)

The password for admin is `baconandcheese`.


## Initial foothold
For this process, the first thing i try is metasploit. Unfortunately, it a no go. 

![eb84270fffc3402b49f185568c38ec40.png](/images/htb/remote/2c62accc265c49968d422aeac0eb36ea.png)

Next, we will search umbraco on searchsploit.


![8ff20821c9ca906bdbcb7dc580518a6e.png](/images/htb/remote/3be1efc6dec54da5b42789c392b38e89.png)


The first exploit is the one i try earlier on msf and its failed. The third one remind me to do important enum which is to get the version of Umbraco CMS. According to mr Tom Fulton here, we can grep Umbraco version on file web.config, which we get from the NFS mount earlier


![e8f22504482ca27a88c283bf896d1e61.png](/images/htb/remote/6d41463edee7413f9a527434059365eb.png)


![7a896d47b46b9e11b96714083d7e0eba.png](/images/htb/remote/bdc738a644a94ce6b45591b16c433638.png)

Looks like it is version 7.12.4 and the second exploit will work,fingers cross. 

Lets just `searchsploit -m 46154` and this will be mirrored in our current path. 



![5554fb51fa015ff716979240eecc6a23.png](/images/htb/remote/24b7235419254321859fb9712149d6b8.png)

Edit the source and change this 3 var to its value, then run this using `python3 46153.py`
