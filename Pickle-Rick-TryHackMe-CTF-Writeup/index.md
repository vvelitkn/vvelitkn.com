# Pickle Rick - TryHackMe CTF Writeup

CTF link: 

[TryHackMe | Pickle Rick](https://tryhackme.com/room/picklerick)

Check ports with nmap 

> nmap -sV -sC 10.10.73.243
> 

<p align="center"> <img src="assets/Untitled.png"> </p>

We found http and ssh port in target server; http port exist so there should be a website. Check it.

<p align="center"> <img src="assets/Untitled%201.png"> </p>

We should look hidden directories in this website. “gobuster” will help. 

> gobuster dir -u [http://10.10.73.243](http://10.10.73.243/) -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,zip
> 

<p align="center"> <img src="assets/Untitled%202.png"> </p>

We found some directories, we should check. And also we should check page source, we can find something useful.

I think we got everythink we need.

<p align="center"> <img src="assets/Untitled%203.png"> </p>

Command panel, we should try something. “ls” maybe

![ls results](Pickle%20Rick%20-%20TryHackMe%20CTF%20Writeup%200dcb24eef32e4a829016576bd46f4ab6/Untitled%204.png"> </p>

ls results

If there is perl we can get reverse shell.

> Source: [https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
> 

We type “which perl” to see if there is perl and where

<p align="center"> <img src="assets/Untitled%205.png"> </p>

In “Source” find PERL and copy code. Don’t forget to change  - Socket;$i="10.0.0.1"; - type your tun0 address and run a listening server.

> nc -lvnp 1234
> 

<p align="center"> <img src="assets/Untitled%206.png"> </p>

Execute. And we got it.

<p align="center"> <img src="assets/Untitled%207.png"> </p>

We found first flag.

<p align="center"> <img src="assets/Untitled%208.png"> </p>

Look around. We found second one.

<p align="center"> <img src="assets/Untitled%209.png"> </p>

We can not cd to root. We should need a solution.

<p align="center"> <img src="assets/Untitled%2010.png"> </p>

We can check what we can do.

> sudo -l
> 

<p align="center"> <img src="assets/Untitled%2011.png"> </p>

We can do whatever we want, so let’s get the bash.

> sudo bash -i
> 

<p align="center"> <img src="assets/Untitled%2012.png"> </p>

We got the root privilage. And got the third flag. Well Done.

<p align="center"> <img src="assets/Untitled%2013.png"> </p>