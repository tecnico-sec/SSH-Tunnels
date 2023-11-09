Instituto Superior Técnico, Universidade de Lisboa

**Network and Computer Security**

<!-- omit in toc -->
# Lab guide: SSH Basics and Tunneling

<!-- omit in toc -->
## Goals

<!-- omit in toc -->
## Index
- [What is SSH?](#what-is-ssh)
- [SSH Basics](#ssh-basics)
  - [Generating Authentication Keys](#generating-authentication-keys)
  - [Accessing a Remote Shell](#accessing-a-remote-shell)
  - [SSH Tunneling](#ssh-tunneling)
    - [Local Port Forwarding](#local-port-forwarding)
    - [Remote Port Forwarding](#remote-port-forwarding)
- [Lab setup](#lab-setup)
  - [Setting the Telnet client](#setting-the-telnet-client)
  - [Setting the Telnet server](#setting-the-telnet-server)
- [Man-in-the-Middle (MitM) attack / ARP poisoning](#man-in-the-middle-mitm-attack--arp-poisoning)
- [Telnet - No SSH tunnel](#telnet---no-ssh-tunnel)
- [Telnet - SSH tunnel](#telnet---ssh-tunnel)

## What is SSH?
Secure Shell (SSH) is a cryptographic network protocol for securely operating network services over an unsecured network. SSH provides a secure channel over an unsecured network in a client-server architecture, connecting an SSH client application with an SSH server. Currently, the most popular SSH implementation is [OpenSSH](https://www.openssh.com) which is the one we are going to use in this tutorial.

When an SSH client connects to an SSH server (also known as sshd), an encrypted SSH tunnel is established. This tunnel allows the client to securely, e.g., run remote commands, transfer files and reroute network traffic.

SSH provides the following three fundamental features that protect against the security issues of eavesdropping and session hijacking:

- **Encryption**: All data, including passwords, are encrypted.
- **Authentication**: By using public/private key pairs, it ensures that you are connecting to the intended remote machine.
- **Integrity**: Protects against data tampering during transmission.

## SSH Basics

### Generating Authentication Keys
**Intuition**: Passwords can be guessed, brute-forced, or even phished. SSH keys, which are essentially long sequences of characters, are much more secure. You keep your private key secret and share the public key with the remote machine.

**Usage**: When passwords are deemed too risky (e.g., due to potential for brute-force attacks), SSH keys provide a more secure alternative. They're often used for automating remote tasks that require authentication.

**Commands**:
```shell
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
**Intuition**: Think of SSH as a secure version of the older ```telnet``` command. When you want to work on a remote server as if you were sitting right in front of it, SSH provides a safe way to do this.

**Usage**: Whenever you need to execute commands on a remote machine, SSH offers a secure means to do so. System administrators might need to access a server located in a data center remotely, developers might need to access a cloud instance, or you might simply want to administer a remote machine.

**Commands**:
```shell
# ssh [user]@[host] -p [port] -i [key_file]
% ssh user@remote_host -p 22 -i ~/.ssh/sirs
# this opens a shell where you can run commands on the remote machine
# type 'exit' to close the shell connection
```

[Further reading](https://www.ssh.com/academy/ssh/command)

### SSH Tunneling
SSH Tunneling, also known as Port Forwarding, is a method to forward arbitrary networking data using an encrypted SSH connection. This can be used to secure network traffic, by adding encryption to legacy applications and unsecure protocols, or to bypass network restrictions, by tunneling non-SSH traffic through an SSH connection, effectively circumventing firewalls or geolocation-based access controls. This approach allows users to access services as if they are local, even if they are on a remote network or behind a firewall.

#### Local Port Forwarding
**Intuition**: You're creating a tunnel from a port on your local machine to a port on a remote server. This means that when you connect to a specific port on your local machine, the connection is forwarded through the SSH tunnel to a specific port on a remote machine.

**Usage**: Imagine a database on a remote server that isn't accessible directly from your machine. Using Local Port Forwarding, you can access the database as if it were running on your local machine.

**Commands**:
```
ssh -L [local_port]:[remote_host]:[remote_port] [username]@[ssh_server]
```

[Further reading](https://www.ssh.com/academy/ssh/tunneling-example#local-forwarding)

#### Remote Port Forwarding
**Intuition**: You're allowing a remote machine to connect to a port on your local machine. This means when something connects to a port on the remote machine (SSH Server), that connection is tunneled through the SSH connection and is forwarded to a port on your local machine.

**Usage**: Let's say you're developing a web application on your local machine and want to show it to a colleague without deploying it. Using Remote Port Forwarding, your colleague can access your local application via a link on their own machine.

**Commands**:
```
ssh -R [remote_port]:[local_host]:[local_port] [username]@[ssh_server]
```

[Further reading](https://www.ssh.com/academy/ssh/tunneling-example#remote-forwarding)

## Lab setup
To carry out this Lab we will create 3 virtual machines. One Telnet client, one Telnet server and one Man-in-the-Middle (MitM).

In our case, we will use the following setup. Obviously, you can adapt your setup and use, for example, other operating systems.

- Telnet client: ubuntu-22.04.3-live-server (command-line interface)
- Telnet server: ubuntu-22.04.3-live-server (command-line interface)
- MitM: kali-linux-2023.3 (useful due to the preinstalled tools for network security like Wireshark)

All virtual machines are set to the network mode "shared network", where traffic is routed directly by the host operating system and the guest shares a VLAN with the host.

### Setting the Telnet client
```
sudo apt install telnet
```

### Setting the Telnet server
```
sudo apt install xinetd telnetd
```

Create `/etc/xinetd.d/telnet` and add the following configuration.
```
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

Finnaly, restart the server.
```
sudo service xinetd restart
```

## Man-in-the-Middle (MitM) attack / ARP poisoning
On the MitM virtual machine we start by finding which machines are in network to find their IPs.
```
sudo netdiscover
```
In our case, for simplicity purposes, we already know the IPs of the other two virtual machines by running, for example, `ip address show` on them. Therefore, we also know the target network address and the subnet mask (in our case, `192.168.64.0/24`) and can filter unnecessary information.
```
sudo netdiscover -r 192.168.64.0/24
```
This will output something like the following. Don't be confused by the fact that we have 3 virtual machines and there are 3 IPs displayed, one of them is in fact the IP of the network interface of the host operating system as a result of the network mode "shared network". Once again, for simplicity purposes, we know that it is the IP `192.168.64.1` so we can exclude it.

![netdiscover output](./netdiscover-output.png "netdiscover output")

Next, enable IP forwarding by running the following command.
```
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

Now we are ready to use Ettercap to carry out an [ARP poisoning](https://en.wikipedia.org/wiki/ARP_spoofing) attack.
```
# pseudo command
sudo ettercap -T -M arp:remote /<target1_ip>// /<target2_ip>//

# more specifically
sudo ettercap -T -M arp:remote /192.168.64.2// /192.168.64.4//
```

If you then use the Telnet client (`192.168.64.2`) to ping the Telnet server (`192.168.64.4`), you will notice packets being sniffed by the MitM.
```
# on the Telnet client
ping 192.168.64.4

# on the MitM terminal where you ran the `ettercap` command
[...]
Thu Nov 1 13:08:02 2023 ［550028］
  192.168.64.2:0 - 192.168.64.4:0| P (0)
[...]
```

## Telnet - No SSH tunnel
Open Wireshark on the MitM virtual machine and start sniffing packets on the corresponding network interface. If you are using Kali Linux, it should be something like `eth0`. Additionaly, set the filter to `telnet`.
![wireshark telnet filter](./wireshark-telnet-filter.png "wireshark telnet filter")

On the Telnet client virtual machine start a telnet connection to the Telnet server. You will be prompted to enter the username and password of the Telnet server virtual machine. In our case, the username is "user" and the password is "password".
```
telnet 192.168.64.4
```

![telnet example](./telnet-example.png "telnet example")

Back in Wireshark, you will notice that packets have been sniffed between the Telnet client and the Telnet server. The `telnet` filter should be enough to filter out irrelevant packets but if you want to be specific use the following, self-explanatory, filter `telnet && ip.src==192.168.64.2`.

Left-click on the first packet sniffed and choose 'Follow > TCP Stream'.

![telnet example](./wireshark-telnet-sniff.png "telnet example")

The output will demonstrate the insecurity of Telnet as you will be able to see the username and the password in plain text, i.e., e.g., not encrypted.

![wireshark telnet sniff output](./wireshark-telnet-sniff-output.png "wireshark telnet sniff output")

Please notice that, some Telnet implementations send each keystroke as a separate packet and therefore, the password will not be clear despite still being there in plain text. See ["character at a time"](https://linux.die.net/man/1/telnet) to learn further.

Please also notice that you can do this using a non graphical tool such as `tcpdump`.
```
# on the MitM terminal, run before establishing the Telnet connection (CTRL+C to stop)
sudo tcpdump -i eth0 -w ./packets.pcap

# find "password" in the packets sniffed
tcpdump -r ./packets.pcap -A | grep -i "password"
```

## Telnet - SSH tunnel
Let us now prove how SSH tunneling adds security to network services, such as Telnet, over an unsecured network.

Keeping the exact same setup from the [previous chapter](#telnet---no-ssh-tunnel), establish a SSH local port forwarding in the Telnet client.
```
ssh -f -N -L 12345:localhost:23 user@192.168.64.4
```
Typically telnet runs on port 23 but if you are unsure which port your Telnet server is using for Telnet run the following command.
```
sudo ss -tulnp
```

For clarity, restart the packet sniffing session on Wireshark and clear the filters.

Now, establish a telnet connection again, but this time using the SSH tunnel created. Once again you will be prompted to enter the username and password of the Telnet server virtual machine.
```
telnet localhost 12345
```

Go back to Wireshark and try to find any Telnet packet. Did you find anything? Probably not. That's ok, because now the packets are being sent through the SSH tunnel. Instead use the Wireshark filter `ssh` and you will notice packets from the Telnet client being sent to the Telnet server. If you open them you will only find encrypted data.
![wireshark telnet ssh sniff output](./wireshark-telnet-ssh-sniff-output.png "wireshark telnet ssh sniff output")

Congratulations, you just secured a Telnet connection. To further prove the point, `telnet` directly to the Telnet server IP instead of the SSH tunnel.
```
telnet 192.168.64.4
```
Capture the packets, filter them using the `telnet` filter and check that once again, you can visualize packets containing the username and password in plain text.

---

**Acknowledgments**:
- [SSH Tunneling Explained](https://goteleport.com/blog/ssh-tunneling-explained/), by Teleport
- [SSH Academy](https://www.ssh.com/academy/ssh), by SSH Communications Security
- [SSH Tunneling - Local & Remote Port Forwarding (by Example)](https://www.youtube.com/watch?v=N8f5zv9UUMI), by Hussein Nasser
- [SSH Essentials: Working with SSH Servers, Clients, and Keys](https://www.digitalocean.com/community/tutorials/ssh-essentials-working-with-ssh-servers-clients-and-keys), by DigitalOcean

---

**Disclaimer**: This tutorial contains portions of text generated by ChatGPT.

---

[SIRS Faculty](mailto:meic-sirs@disciplinas.tecnico.ulisboa.pt)
