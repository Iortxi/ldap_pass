
# LDAP_SNIFF

**Language**
- [Español 🇪🇸](./README_es.md)
- English 🇬🇧

# Overview
Suite of python scripts for LDAP (**NOT LDAPS**) *users* and passwords sniff.

# Index
- [Requirements](#requirements)
- [Scripts](#scripts)
    - [remote_capture.py](#remote_capturepy)
    - [local.py](#localpy)
    - [passwords.py](#passwordspy)
- [Examples](#examples)
    - [remote_capture.py](#remote_capturepy)
    - [local.py](#localpy)
    - [passwords.py](#passwordspy)
    - [Parsed sniffed info](#parsed-sniffed-info)
- [Modules](#modules)
    - [ssh.py](#sshpy)
    - [local.py](#localpy)
    - [paquetes.py](#paquetespy)
    - [rev_dns.py](#rev_dnspy)
    - [utils.py](#utilspy)
- [Gitignore](#gitignore)

# Requirements
**IMPORTANT**: Install the dependencies of `requirements.txt`.
```bash
pip install -r requirements.txt
```

# Scripts
Here the scripts:
- [remote_capture.py](#remote_capturepy)
- [local_capture.py](#local_capturepy)
- [passwords.py](#passwordspy)


## remote_capture.py
It works like this:
1. Establish an SSH connection with a remote server (password or private key). **You need to login as a user that can capture traffic**.
2. It'll look for one traffic capture binary that is installed in the remote server. `snoop`, `tcpdump`, `tshark`, `dumpcap` supported. At [paquetes.py](#paquetespy) you'll find the command execution templates for those binaries, add more if you need to [BUT FOLLOWING SOME RULES](#paquetespy).
3. It'll start the traffic capture at `/tmp/NAME_temp` file at the remote server.
4. It'll wait for you to pick an option:

    0. Stop the traffic capture, bring the remote capture file to local, delete it in the remote server, filter the LDAP traffic and start **another** traffic capture on the remote server (keep executing). Also mix the LDAP traffic just captured with the other capture files (you can choose this option as many times as you want).
    1. The same but stop execution. It'll not start another remote traffic capture.

This uses SSH and SFTP with **paramiko** for **all** the comunication with the remote server.


## local_capture.py
Basically the same as [remote_capture.py](#remote_capturepy) but locally.


## passwords.py
The most simple. It just filters the LDAP passwords from a traffic capture file and prints it (stdout). The capture file you submit can also have *no-LDAP* traffic. Optional reverse DNS resolution.

⚠️: **IT WORKS WITH FILES IN PCAP FORMAT, IF THE CAPTURE FILE YOU SUBMIT IT'S NOT PCAP, IT OVERWRITES IT TO PCAP**


# Examples
Here some execution examples of all the scripts and the info sniffed.

### Parsed sniffed info
Each LDAP packet with a password has this format:
```txt
IP_SOURCE:IP_DESTINATION:LDAP_DN:PASSWORD
```

Example:
```txt
156.131.157.114:121.214.161.142:cn=proxyagent,ou=profile,o=corp:PASs2
131.251.147.188:121.214.161.142:uid=peter,ou=People,o=corp:pass2
```

### remote_capture.py
```bash
# 22 is the default argument (port) for -sshp flag
# -n to disable reverse DNS resolution of IPs
# -v for verbose, see the sniffed and parsed info during execution
# -o for an optional output text file with the sniffed and parsed info. Anyways it'll stay in the mixed capture file
./remote_capture.py -i eth0 -f capture_ldap.pcap -p 389 -s example.com -u peter -pw password -pk id_rsa -pkp "passphrase of the key" [-sshp] 26 -n -v -o output.txt
```

### local_capture.py
```bash
# Same flags without SSH
./local_capture.py -i eth0 -f capture_ldap.pcap -n -v -o output.txt
```

### passwords.py
```bash
./passwords.py -f capture_ldap.pcap -n
```


# Modules
The executable scripts also need a few modules:
- [ssh.py](#sshpy)
- [local.py](#localpy)
- [paquetes.py](#paquetespy)
- [rev_dns.py](#rev_dnspy)
- [utils.py](#utilspy)

## ssh.py
Module that contains all the SSH-related work. It uses [Paramiko](https://www.paramiko.org/) to handle SSH and SFTP connections. It's definitely the best library in python to do that. It also executes the remote commands to capture traffic and remove the evidence in the remote server.

## local.py
The *local* version of [ssh.py](#sshpy). Basically the same without SSH. Way more simpler.

## paquetes.py
**It has the traffic capture commands templates**.
⚠️: **If you wanna add more, please follow the syntax**:
- INTERFAZ is the network interface.
- PUERTO is the port. **ADD THIS FILTER THE LAST ONE IN THE COMMAND**.
- NOMBRE is the capture file name. **ADD THIS ONE THE PENULTIMATE**.
You'll see how is this used at [ssh.py](#sshpy) (comando_remoto() method) and [local.py](#localpy) (comando_escuchador() method).

It does the network packets treatment to filter and write the LDAP packets that contains passwords. It also does the **optional** reverse DNS resolution.

## rev_dns.py
It uses a lot of public DNS servers and a **circular queue** to balance the load of DNS requests. Just one function that resolves reversely an IP to a DNS name and save that info to minimize the DNS requests. If it cannot resolve the IP, just returns the IP.

## utils.py
Auxiliar module with random fuctions.


# Gitignore
It just keeps the `.py`, `README` files and `requirements.txt`.
