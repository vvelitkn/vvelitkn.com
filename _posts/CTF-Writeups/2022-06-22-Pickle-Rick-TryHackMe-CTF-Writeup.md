---
title: "Pickle Rick - TryHackMe CTF Writeup"
classes: wide
header:
  teaser: /assets/images/CTF-Writeups/Pickle-Rick-TryHackMe-CTF-Writeup/logo.jpg
ribbon: MidnightBlue
description: "Check ports with nmap. We found http and ssh port in target server; http port exist so there should be a website..."
categories:
  - CTF Writeups
--- 

CTF link: 

[TryHackMe | Pickle Rick](https://tryhackme.com/room/picklerick)

Check ports with nmap 

> nmap -sV -sC 10.10.73.243
> 

![Untitled](/assets/images/CTF-Writeups/Pickle-Rick-TryHackMe-CTF-Writeup/Untitled.png)

We found http and ssh port in target server; http port exist so there should be a website. Check it.

![Untitled](/assets/images/CTF-Writeups/Pickle-Rick-TryHackMe-CTF-Writeup/Untitled%201.png)

We should look hidden directories in this website. “gobuster” will help. 

> gobuster dir -u [http://10.10.73.243](http://10.10.73.243/) -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,zip
> 

![Untitled](/assets/images/CTF-Writeups/Pickle-Rick-TryHackMe-CTF-Writeup/Untitled%202.png)

We found some directories, we should check. And also we should check page source, we can find something useful.

I think we got everythink we need.

![Untitled](/assets/images/CTF-Writeups/Pickle-Rick-TryHackMe-CTF-Writeup/Untitled%203.png)

Command panel, we should try something. “ls” maybe

![ls results](Pickle%20Rick%20-%20TryHackMe%20CTF%20Writeup%200dcb24eef32e4a829016576bd46f4ab6/Untitled%204.png)

ls results

If there is perl we can get reverse shell.

> Source: [https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
> 

We type “which perl” to see if there is perl and where

![Untitled](/assets/images/CTF-Writeups/Pickle-Rick-TryHackMe-CTF-Writeup/Untitled%205.png)

In “Source” find PERL and copy code. Don’t forget to change  - Socket;$i="10.0.0.1"; - type your tun0 address and run a listening server.

> nc -lvnp 1234
> 

![Untitled](/assets/images/CTF-Writeups/Pickle-Rick-TryHackMe-CTF-Writeup/Untitled%206.png)

Execute. And we got it.

![Untitled](/assets/images/CTF-Writeups/Pickle-Rick-TryHackMe-CTF-Writeup/Untitled%207.png)

We found first flag.

![Untitled](/assets/images/CTF-Writeups/Pickle-Rick-TryHackMe-CTF-Writeup/Untitled%208.png)

Look around. We found second one.

![Untitled](/assets/images/CTF-Writeups/Pickle-Rick-TryHackMe-CTF-Writeup/Untitled%209.png)

We can not cd to root. We should need a solution.

![Untitled](/assets/images/CTF-Writeups/Pickle-Rick-TryHackMe-CTF-Writeup/Untitled%2010.png)

We can check what we can do.

> sudo -l
> 

![Untitled](/assets/images/CTF-Writeups/Pickle-Rick-TryHackMe-CTF-Writeup/Untitled%2011.png)

We can do whatever we want, so let’s get the bash.

> sudo bash -i
> 

![Untitled](/assets/images/CTF-Writeups/Pickle-Rick-TryHackMe-CTF-Writeup/Untitled%2012.png)

We got the root privilage. And got the third flag. Well Done.

![Untitled](/assets/images/CTF-Writeups/Pickle-Rick-TryHackMe-CTF-Writeup/Untitled%2013.png)