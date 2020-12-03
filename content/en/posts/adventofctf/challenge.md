---
author: "faizul"
title: "AdventofCTF by NOVI Hogeschool"
date: 2020-12-03T12:00:06+09:00
description: "24 days of CTF challenge"
draft: false
hideToc: false
enableToc: true
enableTocContent: false
author: faizul
image: images/adventofctf/adventofctf.jpg
tags: 
- adventofctf
- ctf
- web-exploit
categories:
- ctf
---

## Challenge 0 - Teaser
This challenge actually posted before the event started. Its a teaser challenge and worth 1 point after the event started. After digging into old snapshot of the website using wayback machine, we can see that the teaser page. 

Enter adventosctf.com into wayback machine webpage and we can see that there is one snapshot of the page on 12 November

![084d81fb9d91841e156064c8483872a0.png](/images/adventofctf/614bb473eb594f49829f9213db2a6864.png)

click that and we will be served with teaser page
![37662bfdabb6ef5929f81c8e2d2a39c1.png](/images/adventofctf/a35a937abc5f41e192c014caf8dc6796.png)

Dig more into source page, we can find this
![cacb9d741b25fd1945861172e4133bcc.png](/images/adventofctf/11f9cbde63a44b85ad78164ebd46311c.png)

Paste into CyberChef as **from Base64 and we will get the flag ![c3e0c4d68b84aa61b76880ad2786e426.png](/images/adventofctf/0515917714da426f897587e4d4147299.png)

Submit this `NOVI{HEY_1S_Th1S_@_Fla9?}` and we can claim 1 point. 


## Challenge 1 - Day 1
![40ebf1c7852dda9d02270221d5f6985f.png](/images/adventofctf/3bdebe6e0b4b428fa9699c0bcdb60b6f.png)
![15ff82f37a9db88b79e63ca329cc25dd.png](/images/adventofctf//a81a42439a6547c19ffc38872b3f6dc0.png)

- encoded available on source page
![5314bb429b1ef61707c68d2064fe2fe9.png](/images/adventofctf/a621bfc3eedb499496faecb9e3a4a176.png)
```javascript
 <!-- This is an odd encoded thing right? YWR2ZW50X29mX2N0Zl9pc19oZXJl -->
```
To solve this, i use [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
![11d4395dcc9810e9b1d5d7724e5bd36e.png](/images/adventofctf/6f3166a29a0f4d7e8fb8eea1580ffde9.png)

Enter the output on the challenge page and we will get our flag. 
![a5e32bf2d93af65fa73bd54f3b51e372.png](/images/adventofctf/8c0870aaafea4e8ea6b563a25d2d1f33.png)

Submit this flag to get points. You can submit the flag to badge page to get awesome banner.

![1cd4fef1d37fe880de7cd23d37ca8ecb.png](/images/adventofctf/fa58a88adecc4a97af1f7270f736a5bc.png)

## Challenge 2 - Day 2
The second challenge need us to bypass login page.
![0c0a19db945bc87efad0409031a2ea4f.png](/images/adventofctf/ef191805b99e47b1b967d6e80196cb1e.png)

My mistake here is that i didnt read carefully that every challenge is released everyday, yet i unlocked the hints and lose 50 points. So here we go, we are served with login page on the challenge page here. 
![9269f8349fb82016c3860034abbf1acf.png](/images/adventofctf/adb5bc8c29424d1cb740024d68d4ecb4.png)

Doing admin:admin login will gave us this instead. 
![937d2bd607e88f44a4dfd693069b0905.png](/images/adventofctf/f5f2737c64384deead48046042a80f78.png)

Lets look into cookies and crunch the output using CyberChef. 
![8a39ba96ef571610ab4b10827afad351.png](/images/adventofctf/f8cda57eaa944777bdfaeb6a67d6ce24.png)

The output we have is that guest is true and admin is false. Now, what we can do is to change the value of guest is false and admin is true then we have to regenerate the base64 value for the cookie. 
![31a9bb070d7c215749fcda84ce399e78.png](/images/adventofctf/c685949c7603453696cf43c223016ab3.png)
new cookie value is `eyJndWVzdCI6ImZhbHNlIiwiYWRtaW4iOiJ0cnVlIn0=`

Then, we paste this into cookie value on the challenge page then we can get the flag

![144f60e136f9ff9539991ef0980dd6e2.png](/images/adventofctf/0f924b726d4349b3ad9856b5e0c7adce.png)

Submit to the badge page and get our awesome daily badge. 

![860e2eaf429c8ccd8c257eb13e59d23e.png](/images/adventofctf/79e5467b7b6945d28cc71293f3307650.png)

## Challenge 3 - Day 3
The third challenge will require us to do another login bypass.
![575f2d120f4bc4154d19321adb99e578.png](/images/adventofctf/50211f24507949aca326b420b85e905f.png)

![4ef46bcb5148e1d9c1988a36ac8c9fcf.png](/images/adventofctf/a809cb99331f4454ad55b5d428fba9ec.png)

Challenge 3 writeup will be released after day 4

![e8f397b6e289bea5fbde6891641a03b6.png](/images/adventofctf/a7e73505a70547cc82eb2adfa4201822.png)