# Deathnote CTF Writeup

CTF link: 

[Deathnote: 1](https://www.vulnhub.com/entry/deathnote-1,739/)

- We launched target machine and our kali and opened terminal as root.
- Check ifconfig and grab your ip address and start a scan.

> netdiscover -r xx.xx.xx.0/24
> 
- Pick the ip address and copy it.

We have to check ip for which ports runs which apps.

- First we check nmap

> nmap -sV -sC xx.x.x.x

<p align="center"> <img src="assets/Untitled.png"> </p>

- We see our ip runs ssh at port 22 and http at port 80

We see that http port, we should check our ip address if it runs a website.

<p align="center"> <img src="assets/Untitled%201.png"> </p>

It runs but redicts to deathnote.vuln/wordpress so we should add our ip as this link to /etc/hosts file. We mapped our target ip address to deathnote.vuln.

> echo “10.0.2.4 deathnote.vuln” > /etc/hosts
> 

<p align="center"> <img src="assets/Untitled%202.png"> </p>

We have a wordpress website, we should use wpscan but first let’s check /wp-content/uploads where every file uploaded file’s storage. 

<p align="center"> <img src="assets/Untitled%203.png"> </p>

Okey we found these two files, probably we found usernames and passwords for brute-force attack. We have a website and a ssh connection. We will attack them till we found something. So we copy these two files to our file named “deathnote” (just for being organized).

We should check wpscan for another details.

> wpscan —url http://deathnote.vuln/wordpress
> 

<p align="center"> <img src="assets/Untitled%204.png"> </p>

Nothing interesting, so we will try usernames and passwords for wp-admin or wp-login (wordpress login pages for default).

> wpscan -U user.txt -P pass.txt --url http://deathnote.vuln/wordpress/ --password-attack wp-login
> 

<p align="center"> <img src="assets/Untitled%205.png"> </p>

We couldn’t find a combination so we can try to attack ssh. We will use “hydra” tool.

> hydra -L user.txt -P pass.txt ssh://10.0.2.4
> 

<p align="center"> <img src="assets/Untitled%206.png"> </p>

We found a combination, we can connect the server with ssh.

> ssh l@10.0.2.4
> 

<p align="center"> <img src="assets/Untitled%207.png"> </p>

Can we run sudo? No…

<p align="center"> <img src="assets/Untitled%208.png"> </p>

When we check what is there we found user.txt which written with brainfuck language. We will use online tools to decode.

<p align="center"> <img src="assets/Untitled%209.png"> </p>

<p align="center"> <img src="assets/Untitled%2010.png"> </p>

Kira approved that we found the shell, we will go and go back and go back and try to find a useful file/files for any clue.

<p align="center"> <img src="assets/Untitled%2011.png"> </p>

Okey, we found something. Check the fake-notebook-rule folder.

<p align="center"> <img src="assets/Untitled%2012.png"> </p>

<p align="center"> <img src="assets/Untitled%2013.png"> </p>

We found a password for probably kira. 

<p align="center"> <img src="assets/Untitled%2014.png"> </p>

We found something, maybe root’s password. Try it.

<p align="center"> <img src="assets/Untitled%2015.png"> </p>

Can we “sudo su root” just for try

<p align="center"> <img src="assets/Untitled%2016.png"> </p>

We got it.

<p align="center"> <img src="assets/Untitled%2017.png"> </p>