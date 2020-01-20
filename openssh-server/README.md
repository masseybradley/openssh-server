# OpenSSH

[OpenSSH](https://www.openssh.com/) is the premier connectivity tool for remote login with the SSH protocol. 

## TL;DR

```console
$ helm install openssh-server .
```

## Introduction

This chart bootstraps an OpenSSH deployment on a [Kubernetes](https://kubernetes.io/) cluster using the [Helm](https://helm.sh) package manager.


## Prerequisites

- Kubernetes 1.15+
- Helm 2.11+ or Helm 3.0-beta3+
- PV provisioner support in the underlying infrastructure

## Installing the Chart

To install the chart with the release name `my-release`:

```console
$ helm install --name my-release openssh-server .
```

The command deploys OpenSSH on the Kubernetes cluster in the default configuration. The [Parameters](#parameters) section lists the parameters that can be configured during installation.

> **Tip**: List all releases using `helm list`

## Uninstalling the Chart

To uninstall/delete the `my-release` deployment:

```console
$ helm delete --purge my-release
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

## Parameters

The following tables lists the configurable parameters of the OpenSSH chart and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of OpenSSH server replicas | `1` |
| `image.repository` | OpenSSH server image name | `build.yields.io/openssh-server` |
| `image.tag` | OpenSSH server image tag | `latest` |
| `image.pullPolicy` | OpenSSH server image pull policy | `IfNotPresent` |
| `image.pullSecrets` | OpenSSH server image pull secrets | `[]` |
| `nameOverride` | String to partially override openssh-server.fulname template | `""` |
| `fullnameOverride` | String to fully override openssh-server.fullname template | `""` |
| `service.type` | Kubernetes service type | `ClusterIP` |
| `ingress.enabled`: `false`
| `ingress.annotations`: `{}`
| `ingress.hosts`: `[]`
| `ingress.hosts.host`: `chart-example.local`
| `ingress.hosts.paths`: `[]`
| `ingress.tls`: `[]`
| `ingress.tls.secretName`: `chart-example-tls`
| `ingress.tls.hosts`: `[]`
| `resources`: `{}`
| `nodeSelector`: `{}`
| `tolerations`: `[]`
| `affinity`: `{}`
| `sshd.port`: `22` |
| `sshd.protocol`: `2` |
| `sshd.addressFamily`: `any` |
| `sshd.ipv4.enabled`: `true` |
| `sshd.ipv4.listenAddress`: `0.0.0.0` |
| `sshd.ipv6.enabled`: `true` |
| `sshd.ipv6.listenAddress`: `"::"` |
| `sshd.kexAlgorithms`: `diffie-hellman-group-exchange-sha256` |
| `sshd.ciphers`: `aes256-cbc,aes256-ctr` |
| `sshd.messageAuthenticationCodes`: `hmac-sha2-256-etm@openssh.com,hmac-sha2-256` |
| `sshd.hostKeys`: `[/etc/ssh/ssh_host_rsa_key, /etc/ssh/ssh_host_ecdsa_key, /etc/ssh/ssh_host_ed25519_key]` |
| `sshd.reKeyLimit`: `default none` |
| `sshd.sysLogFacility`: `AUTH` |
| `sshd.logLevel`: `INFO` |
| `sshd.loginGraceTime`: `2m` |
| `sshd.permitRootLogin`: `prohibit-password` |
| `sshd.strictModes`: `yes` |
| `sshd.maxAuthTries`: `6` |
| `sshd.maxSessions`: `10` |
| `sshd.pubKeyAuthentication`: `yes` |
| `sshd.authorizedKeysFile`: `.ssh/authorized_keys .ssh/authorized_keys2` |
| `sshd.authorizedPrincipalsFile`: `none` |
| `sshd.authorizedKeysCommand`: `none` |
| `sshd.authorizedKeysCommandUser`: `nobody` |
| `sshd.hostBasedAuthentication`: `no` |
| `sshd.ignoreUserKnownHosts`: `no` |
| `sshd.ignoreRhosts`: `true` |
| `sshd.passwordAuthentication`: `false` |
| `sshd.permitEmptyPasswords`: `false` |
| `sshd.challengeResponseAuthentication`: `false` |
| `sshd.kerberosAuthentication.enabled`: `false` |
| `sshd.kerberosAuthentication.orLocalPassword`: `true` |
| `sshd.kerberosAuthentication.ticketCleanup`: `true` |
| `sshd.kerberosAuthentication.getAFSToken`: `false` |
| `sshd.gssApiAuthentication.enabled`: `false` |
| `sshd.gssApiAuthentication.cleanupCredentials`: `true` |
| `sshd.gssApiAuthentication.strictAcceptorCheck`: `true` |
| `sshd.gssApiAuthentication.keyExchange`: `false` |
| `sshd.usePam`: `true` |
| `sshd.allowAgentForwarding`: `true` |
| `sshd.allowTcpForwarding`: `true` |
| `sshd.gatewayPorts`: `false` |
| `sshd.x11Forwarding`: `true` |
| `sshd.x11DispalyOffset`: `10` |
| `sshd.x11UseLocalhost`: `true` |
| `sshd.permitTTY`: `true` |
| `sshd.printMotd`: `false` |
| `sshd.printLastLog`: `true` |
| `sshd.tcpKeepAlive`: `true` |
| `sshd.useLogin`: `false` |
| `sshd.permitUserEnvironment`: `false` |
| `sshd.compression`: `delayed` |
| `sshd.clientAliveInterval`: `0` |
| `sshd.clientAliveMaxCount`: `3` |
| `sshd.useDNS`: `false` |
| `sshd.pidFile`: `/var/run/sshd.pid` |
| `sshd.maxStartups`: `10:30:100` |
| `sshd.permitTunnel`: `false` |
| `sshd.chrootDirectory`: `none` |
| `sshd.versionAddendum`: `none` |
| `sshd.banner`: `none` |
| `sshd.acceptEnv.enabled`: `true` |
| `sshd.acceptEnv.variables`: `[LANG, LC_*]` |
| `sshd.subsystems.enabled`: `true` |
| `sshd.subsystems.systems.name`: `sftp` |
| `sshd.subsystems.systems.value`: `/usr/lib/openssh/sftp-server` |
| `sshd.matchUser.enabled`: `false` |
| `sshd.matchUser.users`: `{}` |
| `sshd.matchUser.users.name`: `""` |
| `sshd.matchUser.users.settings`: `{}` |
| `sshd.matchUser.users.settings.name`: `""` |
| `sshd.matchUser.users.settings.value`: `""` |
| `authorized_keys`: `[]` |
