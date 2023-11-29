Instituto Superior Técnico, Universidade de Lisboa

**Network and Computer Security**

<!-- omit in toc -->
# Lab guide: SSH Tunneling

<!-- omit in toc -->
## Goals

- Learn the fundamentals of the SSH protocol, including key generation, remote shell access, and tunneling (sometimes called port forwarding);
- Perform a Adversary-in-the-Middle (AitM) attack in a simulated setting to demonstrate the security vulnerabilities of the Telnet protocol;
- Create an SSH tunnel and reroute the Telnet traffic through it to demonstrate the security provided by SSH.

<!-- omit in toc -->
## Index

- [Introduction](#introduction)
- [What is SSH?](#what-is-ssh)
- [SSH in practice](#ssh-in-practice)
  - [Generating Authentication Keys](#generating-authentication-keys)
  - [Accessing a Remote Shell](#accessing-a-remote-shell)
  - [SSH Tunneling](#ssh-tunneling)
    - [Local Port Forwarding](#local-port-forwarding)
    - [Remote Port Forwarding](#remote-port-forwarding)
- [Lab setup](#lab-setup)
  - [Setup of the Telnet client](#setup-of-the-telnet-client)
  - [Setup of the Telnet server](#setup-of--the-telnet-server)
- [Adversary-in-the-Middle (AitM) attack / ARP poisoning](#adversary-in-the-middle-AitM-attack--arp-poisoning)
- [Telnet without protection](#telnet-without-protecion)
- [Telnet protected with SSH](#telnet-protected-with-SSH)
- [Conclusion](#conclusion)

## Introduction

In the digital age, where cyber threats loom at every corner of the network, it is crucial to understand the principles of secure communication.
In regard to remote terminal protocols, two names come up: Telnet and SSH.

Telnet, one of the earliest remote login protocols, lacks mechanisms to protect data from eavesdroppers on the network.
SSH (Secure SHell), on the other hand, was designed with security at its core, providing a robust suite of features that ensure confidentiality, integrity, and authentication.

This lab guide will explore the vulnerabilities of Telnet and show how SSH can shield and secure those same communications.

## What is SSH?

[Secure Shell (SSH)](https://en.wikipedia.org/wiki/Secure_Shell) is a cryptographic network protocol for securely operating network services.
SSH provides a secure channel over an unsecured network in a client-server architecture, connecting an SSH client application with an SSH server.
Currently, the most popular SSH implementation is [OpenSSH](https://www.openssh.com) which is the one we are going to use in this tutorial.

When an SSH client connects to an SSH server (or daemon, abbreviated as sshd), an encrypted SSH tunnel is established.
This tunnel allows the client to securely run remote commands, transfer files and reroute network traffic.

SSH provides the following three fundamental features that protect against the security issues of an [Adversary-in-the-Middle (AitM)](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) attack:

- **Encryption**: All data, including passwords, are encrypted;
- **Authentication**: By using public/private key pairs, it ensures that you are connecting to the intended remote machine;
- **Integrity**: Protects against data tampering during transmission.

## SSH in practice

### Generating Authentication Keys

Passwords can be guessed, brute-forced, or even phished.
SSH keys, which are essentially long sequences of characters representing large numbers, are much more secure.
You keep your private key secret and share the public key with the remote machine.

When passwords are deemed too risky (e.g., due to potential for brute-force attacks), SSH keys provide a more secure alternative.
They are often used for automating remote tasks that require authentication.

**Commands**:

```sh
# ssh-keygen -t [asymmetric_key_algorithm] -b [key_size] -f [key_file]
% ssh-keygen -t rsa -b 2048 -f ~/.ssh/sirs
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in ~/.ssh/sirs
Your public key has been saved in ~/.ssh/sirs.pub
The key fingerprint is:
[...]

# ssh-copy-id -i ~/.ssh/[key_file] [user]@[host]
% ssh-copy-id -i ~/.ssh/sirs user@remote_host
# alternatively, you can copy your public key to the server's ~/.ssh/authorized_keys
```

[Further reading](https://www.ssh.com/academy/ssh/keygen)

### Accessing a Remote Shell

SSH provides a secure way to work on a remote server as if you were sitting right in front of it.
Think of it as a secure version of the older `telnet` command.

Whenever you need to execute commands on a remote machine, SSH offers a secure means to do so.
For example, system administrators might need to access a server located in a data center remotely, and developers might need to access a virtual machine running in a cloud instance.

**Commands**:

```sh
# ssh [user]@[host] -p [port] -i [key_file]
% ssh user@remote_host -p 22 -i ~/.ssh/sirs
# this opens a shell where you can run commands on the remote machine
# type 'exit' to close the shell connection
```

[Further reading](https://www.ssh.com/academy/ssh/command)

### SSH Tunneling

SSH Tunneling, also known as Port Forwarding, is a method to forward arbitrary network data using an encrypted SSH connection.
This can be used to secure network traffic, by adding transparent encryption to legacy applications and unsecure protocols.
It can also be used to bypass network restrictions, by tunneling non-SSH traffic through an SSH connection, effectively circumventing firewalls or geolocation-based access controls.
This approach allows users to access services as if they are local, even if they are on a remote network or behind a firewall.

#### Local Port Forwarding

You are creating a tunnel from a port on your local machine to a port on a remote server.
This means that when you connect to a specific port on your local machine, the connection is forwarded through the SSH tunnel to a specific port on a remote machine.

A useful example for this is a database on a remote server that is not accessible directly from your machine.
Using Local Port Forwarding, you can access the database as if it were running on your local machine.

**Commands**:

```sh
# remote_host is in the context of the ssh_server, i.e., the address of the remote resource we want to connect to is from the perspective of the SSH server
ssh -L [local_port]:[remote_host]:[remote_port] [username]@[ssh_server]
```

[Further reading](https://www.ssh.com/academy/ssh/tunneling-example#local-forwarding)

#### Remote Port Forwarding

You are allowing a remote machine to connect to a port on your local machine.
This means that when something connects to a port on the remote machine (SSH Server), that connection is tunneled through the SSH connection and is forwarded to a port on your local machine.

Let us say you are developing a web application on your local machine and want to show it to a colleague without deploying it.
Using Remote Port Forwarding, your colleague can access your local application via a link on their own machine.

**Commands**:

```sh
# local_host does not necessarily imply your actual machine (localhost)
# local_host can be any resource within your local network
ssh -R [remote_port]:[local_host]:[local_port] [username]@[ssh_server]
```

[Further reading](https://www.ssh.com/academy/ssh/tunneling-example#remote-forwarding)

## Lab setup

To carry out this lab we will create 3 virtual machines (VMs):
one Telnet client, one Telnet server, and one Adversary-in-the-Middle (AitM) attacker.

In our case, we will use the following setup.
Obviously, you must adapt your setup and use, e.g., other operating systems.

- Telnet client: ubuntu-22.04.3-live-server (lightweight since it is a command-line interface);
- Telnet server: ubuntu-22.04.3-live-server (lightweight since it is a command-line interface);
- AitM: kali-linux-2023.3 (useful due to the preinstalled tools for network security like Wireshark and Ettercap)

All VMs are set to the network mode _"shared network"_, where traffic is routed directly by the host operating system and the guest shares a VLAN with the host.

### Setup of the Telnet client

```sh
sudo apt install telnet
```

### Setup of the Telnet server

```sh
sudo apt install xinetd telnetd
```

Create `/etc/xinetd.d/telnet` and add the following configuration:

```txt
service telnet
{
    disable         = no
    flags           = REUSE
    socket_type     = stream        
    wait            = no
    user            = root
    server          = /usr/sbin/in.telnetd
    log_on_failure  += USERID
}
```

Finally, restart the server.

```sh
sudo service xinetd restart
```

## Adversary-in-the-Middle (AitM) attack / ARP poisoning

On the AitM VM we start by scanning the network to find the IPs of the machines in it.

```sh
sudo netdiscover
```

In our case, for simplicity purposes, we already know the IPs of the other two VMs by running, for example, `ip address show` on them.
Therefore, we also know the target network address and the subnet mask (in our case, `192.168.64.0/24`) and can filter out unnecessary information.

```sh
sudo netdiscover -r 192.168.64.0/24
```

This will output something like the following.
Do not be confused by the fact that we have 3 VMs and there are 3 IPs displayed, one of them is in fact the IP of the network interface of the host operating system.
This is due to the network mode being set to "shared network".
Once again, for simplicity purposes, we know that it is the IP `192.168.64.1` so we can exclude it.

![netdiscover output](./images/netdiscover-output.png 'netdiscover output')

Next, enable IP forwarding by running the following command:

```sh
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

Now we are ready to use [Ettercap](https://en.wikipedia.org/wiki/Ettercap_(software)) to carry out an [ARP poisoning](https://en.wikipedia.org/wiki/ARP_spoofing) attack effectively allowing for a MitM attack.

```sh
# pseudo command
sudo ettercap -T -M arp:remote /<target_ip_1>// /<target_ip_2>//

# more specifically
sudo ettercap -T -M arp:remote /192.168.64.2// /192.168.64.4//
```

If you then use the Telnet client VM (`192.168.64.2`) to ping the Telnet server VM (`192.168.64.4`), you will notice packets being sniffed by the AitM VM.

```sh
# on the Telnet client VM
ping 192.168.64.4

# on the MitM VM terminal where you ran the ettercap command
[...]
Thu Nov 1 13:08:02 2023 ［550028］
  192.168.64.2:0 - 192.168.64.4:0| P (0)
[...]
```

## Telnet without protection

Open [Wireshark](https://en.wikipedia.org/wiki/Wireshark) on the AitM VM and start sniffing packets on the correct network interface.
If you are using Kali Linux, it should be something like `eth0`.
Additionaly, set the filter to `telnet`.

<p align='center'>
  <img src='./images/wireshark-telnet-filter.png' alt='wireshark telnet filter' title='wireshark telnet filter' width="60%">
</p>

On the Telnet client VM start a Telnet connection to the Telnet server VM.
You will be prompted to enter the username and password of the Telnet server VM.
In our case, the username is "user" and the password is "password".

```sh
telnet 192.168.64.4
```

![telnet example](./images/telnet-example.png 'telnet example')

Back in Wireshark, you will notice that packets have been sniffed between the Telnet client and the Telnet server.
The `telnet` filter should be enough to filter out irrelevant packets but if you want to be specific use the following, self-explanatory, filter: `telnet && ip.src==192.168.64.2`.

Left-click on the first packet sniffed and choose `Follow > TCP Stream`.

![wireshark telnet sniff](./images/wireshark-telnet-sniff.png 'wireshark telnet sniff')

The output will demonstrate the main security vulnerability of the Telnet protocol as you will be able to see the username and the password in plain text, i.e., not encrypted.

![wireshark telnet sniff output](./images/wireshark-telnet-sniff-output.png 'wireshark telnet sniff output')

Please notice that, some Telnet implementations send each keystroke as a separate packet and therefore, the password will not be clear despite still being there in plain text. See ["character at a time"](https://linux.die.net/man/1/telnet) to learn further.

Please also notice that, instead of Wireshark, you can do this demonstration using a non-graphical tool such as `tcpdump`.

```sh
# on the MitM VM terminal, run before establishing the Telnet connection (CTRL+C to stop)
sudo tcpdump -i eth0 -w ./packets.pcap

# establish the Telnet connection between the Telnet client VM and the Telnet server VM as previously shown

# find "password" in the packets sniffed
tcpdump -r ./packets.pcap -A | grep -i "password"
```

## Telnet protected with SSH tunnel

Let us now show how SSH tunneling adds security to network services, such as Telnet, over an unsecured network.

Keep the exact same setup from the previous section, establish an SSH local port forwarding in the Telnet client VM.

```sh
# localhost because the destination resource is the SSH server itself
ssh -f -N -L 12345:localhost:23 user@192.168.64.4
```

Typically, Telnet runs on port 23, but if you are unsure which port your Telnet server VM is using for Telnet, run the following command.

```sh
sudo ss -tulnp
```

For clarity, restart the packet sniffing session on Wireshark and clear the filters.

Now, establish a Telnet connection again, but this time using the SSH tunnel created.
Once again you will be prompted to enter the username and password of the Telnet server VM.

```sh
telnet localhost 12345
```

Go back to Wireshark and try to find any Telnet packet.
Did you find anything?
Probably not.
That is the expected result, because now the packets are being sent through the SSH tunnel.
Instead, use the Wireshark filter `ssh` and you will notice packets from the Telnet client being sent to the Telnet server.
If you open them you will only find encrypted data.

![wireshark telnet ssh sniff output](./images/wireshark-telnet-ssh-sniff-output.png 'wireshark telnet ssh sniff output')

Congratulations, you just secured a Telnet connection.
To further prove the point, `telnet` directly to the Telnet server VM IP instead of the SSH tunnel.

```sh
telnet 192.168.64.4
```

Capture the packets, filter them using the `telnet` filter and check that once again, you can visualize packets containing the username and password in plain text.

## Conclusion

Telnet, an older protocol used for accessing remote servers, operates in plaintext.
This means that all data, including sensitive information like usernames and passwords, are transmitted over the network without any form of encryption.
This lab vividly demonstrated how an Adversary-in-the-Middle (AitM) attack could exploit this vulnerability to capture credentials and compromise the content of the network communication.

SSH provides a secure alternative to Telnet with three critical features: encryption, authentication, and integrity.
Through SSH tunneling, we can create secure pathways for insecure protocols like Telnet, effectively encrypting data that was previously transmitted in plaintext.

In a learning setting, implementing these security mechanisms from scratch is a valuable educational exercise, allowing students to understand the mechanics of network security at a granular level. However, in real-world applications, it would be impractical and risky to attempt to replicate what well-established protocols like SSH already provide. SSH is not only secure but also widely tested and trusted in production environments.

---

**References**:

- [SSH Tunneling Explained](https://goteleport.com/blog/ssh-tunneling-explained/), by Teleport
- [SSH Academy](https://www.ssh.com/academy/ssh), by SSH Communications Security
- [SSH Tunneling - Local & Remote Port Forwarding (by Example)](https://www.youtube.com/watch?v=N8f5zv9UUMI), by Hussein Nasser
- [SSH Essentials: Working with SSH Servers, Clients, and Keys](https://www.digitalocean.com/community/tutorials/ssh-essentials-working-with-ssh-servers-clients-and-keys), by DigitalOcean

---

[SIRS Faculty](mailto:meic-sirs@disciplinas.tecnico.ulisboa.pt)
