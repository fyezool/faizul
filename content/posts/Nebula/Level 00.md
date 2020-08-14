+++
title = "Nebula - Exploit-exercise"
date = "2020-08-14"
+++

Depress and isolating from other human person create a huge amount of free time for me to pursue further my passion in Cybersecurity. This time, i alocate some of it to write about my Exploit-Exercise whih you can found [here](https://exploit-exercises.lains.space/)

Basically, exploit exercise have 3 main exercise which are Nebula, Protostar and Fusion. Nebula is focusing more on Privilege Escalation in Linux.

## Level 00

## Questions
`Alternatively, look at the find man page. To access this level, log in as level00 with the password of level00.`

## Lab setup
First, lets login to the machine. Since i setup the lab on VMWare Workstation, i just put the machine behind NAT connection and scan the network using `netdiscover`. 

## Connect via ssh
![43361a1d4008fab25182ed509f7fdc1f.png](deb9f10bc41343eb8579e82c14f50070.png)

Login using `level00:level00` on ssh and we are in into the machine now.

## Lets get started

The first level on Nebula would be very basic Linux Privilege Escalation technique. Lets try to use `find / -user flag00 -perm -4000`

Quick rundown on the command, `find` is the tools you can found on linux, just like `locate` and `ls`. Then, `/` is on the next queue which indicate that find will crawl over the root `/` of the filesystem. 

Since the instruction needed us to execute this on behalf of `flag00`, here we just indicate `-user flag00` and its following permission `-perm` plus the value of setuid and octal of `-4000`.


Now, this will create a pile of hateful output, we can filter this using `-print 2> /dev/null`. `/dev/null` is kinda black hole in Linux and redirect anything to it can create nice and neat filter. 

![12b4d7f77a0728265b5e81aaef7bbfcc.png](30868d96f2f94e9186e5d754603b1945.png)

Ok, we have found the binary, lets run it and get our flag shall we.

![19d9c43b0a6b459bf064545cdb5ea0d3.png](6710313549ba4d07a1a929854c8d0ec2.png)

We are already become user flag00 and lets just execute `getflag` to get the flag and move to next level. 


## Exploited

we managed to exploit this and reach our target

![2d8c0cc5e43ac2a6d36d08f4238fe43c.png](9bd023d676d549efb099c5ccf1a8e3f8.png)


## Conclusion
- SUID is awesome

## Reference
- https://www.linuxnix.com/suid-set-suid-linuxunix/