---
title: "Deathnote CTF Write-up"
classes: wide
header:
  teaser: /assets/images/CTF-Writeups/Deathnote-CTF-Writeup/logo.jpg
ribbon: MidnightBlue
description: "We launch target machine and our kali and opened terminal as root. Check ifconfig and grab your ip address and start a scan...."
categories:
  - CTF Writeups
---

CTF link: 

[Deathnote: 1](https://www.vulnhub.com/entry/deathnote-1,739/)

- We launch target machine and our kali and opened terminal as root.
- Check ifconfig and grab your ip address and start a scan.

> netdiscover -r xx.xx.xx.0/24
> 
- Pick the ip address and copy it.

We have to check ip for which ports runs which apps.

- First we check nmap

> nmap -sV -sC xx.x.x.x

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled.png)

- We see our ip runs ssh at port 22 and http at port 80

We see that http port, we should check our ip address if it runs a website.

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%201.png)

It runs but redicts to deathnote.vuln/wordpress so we should add our ip as this link to /etc/hosts file. We mapped our target ip address to deathnote.vuln.

> echo “10.0.2.4 deathnote.vuln” > /etc/hosts
> 

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%202.png)

We have a wordpress website, we should use wpscan but first let’s check /wp-content/uploads where every file uploaded file’s storage. 

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%203.png)

Okey we found these two files, probably we found usernames and passwords for brute-force attack. We have a website and a ssh connection. We will attack them till we found something. So we copy these two files to our file named “deathnote” (just for being organized).

We should check wpscan for another details.

> wpscan —url http://deathnote.vuln/wordpress
> 

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%204.png)

Nothing interesting, so we will try usernames and passwords for wp-admin or wp-login (wordpress login pages for default).

> wpscan -U user.txt -P pass.txt --url http://deathnote.vuln/wordpress/ --password-attack wp-login
> 

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%205.png)

We couldn’t find a combination so we can try to attack ssh. We will use “hydra” tool.

> hydra -L user.txt -P pass.txt ssh://10.0.2.4
> 

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%206.png)

We found a combination, we can connect the server with ssh.

> ssh l@10.0.2.4
> 

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%207.png)

Can we run sudo? No…

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%208.png)

When we check what is there we found user.txt which written with brainfuck language. We will use online tools to decode.

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%209.png)

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%2010.png)

Kira approved that we found the shell, we will go and go back and go back and try to find a useful file/files for any clue.

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%2011.png)

Okey, we found something. Check the fake-notebook-rule folder.

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%2012.png)

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%2013.png)

We found a password for probably kira. 

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%2014.png)

We found something, maybe root’s password. Try it.

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%2015.png)

Can we “sudo su root” just for try

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%2016.png)

We got it.

![Untitled](/assets/images/CTF-Writeups/Deathnote-CTF-Writeup/Untitled%2017.png)