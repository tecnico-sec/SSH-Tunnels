Instituto Superior Técnico, Universidade de Lisboa

**Network and Computer Security**

<!-- omit in toc -->
# Lab guide: SSH Basics and Tunneling

<!-- omit in toc -->
## Goals
- [What is SSH?](#what-is-ssh)
- [SSH Basics](#ssh-basics)
  - [Generating Authentication Keys](#generating-authentication-keys)
  - [Accessing a Remote Shell](#accessing-a-remote-shell)
  - [scp (Secure Copy Protocol)](#scp-secure-copy-protocol)
  - [ssh-agent](#ssh-agent)
  - [Config File](#config-file)
- [SSH Tunneling](#ssh-tunneling)
  - [Local Port Forwarding](#local-port-forwarding)
  - [Remote Port Forwarding](#remote-port-forwarding)
  - [Dynamic Port Forwarding](#dynamic-port-forwarding)
- [Case Scenarios](#case-scenarios)

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

### scp (Secure Copy Protocol)

### ssh-agent

### Config File

## SSH Tunneling
SSH Tunneling, also known as Port Forwarding, is a method to forward arbitrary networking data using an encrypted SSH connection. This can be used to secure network traffic, by adding encryption to legacy applications and unsecure protocols, or to bypass network restrictions, by tunneling non-SSH traffic through an SSH connection, effectively circumventing firewalls or geolocation-based access controls. This approach allows users to access services as if they are local, even if they are on a remote network or behind a firewall.

### Local Port Forwarding
**Intuition**: You're creating a tunnel from a port on your local machine to a port on a remote server. This means that when you connect to a specific port on your local machine, the connection is forwarded through the SSH tunnel to a specific port on a remote machine.

**Usage**: Imagine a database on a remote server that isn't accessible directly from your machine. Using Local Port Forwarding, you can access the database as if it were running on your local machine.

**Commands**:
```
ssh -L [local_port]:[remote_host]:[remote_port] [username]@[ssh_server]
```

[Further reading](https://www.ssh.com/academy/ssh/tunneling-example#local-forwarding)

### Remote Port Forwarding
**Intuition**: You're allowing a remote machine to connect to a port on your local machine. This means when something connects to a port on the remote machine (SSH Server), that connection is tunneled through the SSH connection and is forwarded to a port on your local machine.

**Usage**: Let's say you're developing a web application on your local machine and want to show it to a colleague without deploying it. Using Remote Port Forwarding, your colleague can access your local application via a link on their own machine.

**Commands**:
```
ssh -R [remote_port]:[local_host]:[local_port] [username]@[ssh_server]
```

[Further reading](https://www.ssh.com/academy/ssh/tunneling-example#remote-forwarding)

### Dynamic Port Forwarding

## Case Scenarios

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
