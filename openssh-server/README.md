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

The following tables lists the configurable parameters of the OpenSSH chart and their default values. The default values are the non-standard Debian options (`man sshd_config`).

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
| `sshd.port` | Specifies the port number that `sshd` listens on. The default is 22. `22` |
| `sshd.protocol` | Specifies the SSH protocol version | `2` |
| `sshd.addressFamily` | Specifies which address family should be used by `sshd` | `any` |
| `sshd.ipv4.enabled` | Enables binding to the IPv4 interface | `true` |
| `sshd.ipv4.listenAddress` | Specifies the local IPv4 addresses `sshd` should listen on | `0.0.0.0` |
| `sshd.ipv6.enabled` | Enables binding to the IPv6 interface | `true` |
| `sshd.ipv6.listenAddress` | Specified the local IPv6 addresses `sshd` should listen on | `"::"` |
| `sshd.kexAlgorithms` | Specifies the available KEX (Key Exchange) algorithms. The default is "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1". | `nil` |
| `sshd.ciphers` | Specifies the allowed ciphers. The default is "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com" | `nil` |
| `sshd.messageAuthenticationCodes` | Specifies the available MAC (message authentication code) algorithms. The default is "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1". | `nil` |
| `sshd.reKeyLimit` | Specifies the maximum amount of data that may be transmitted before the session key is renegotiated, optionally followed by a maximum amount of time that may pass before the session key is renegotiated. The default is "default none". | `nil` |
| `sshd.sysLogFacility` | Gives the facility code that is used when logging messages from `sshd`. The default is AUTH. | `nil` |
| `sshd.logLevel` | Specifies the verbosity level the is used when logging messages from `sshd`. The default is INFO. | `nil` |
| `sshd.loginGraceTime` | The server disconnects after this time if the user has not successfully logged in. The default it 120 seconds. | `nil` |
| `sshd.permitRootLogin` | Specifies whether root can login using `ssh`. The default is prohibit-password. |  `no` |
| `sshd.strictModes` | Specifies whether `sshd` should check file modes and ownership of the user's files and home directory before accepting login. The default is yes. | `nil` |
| `sshd.maxAuthTries` | Specifies the maximum number of authentication attempts permitted per connection. The default is 6. | `nil` |
| `sshd.maxSessions` | Specifies the maximum number of open shell, login or subsystem (e.g. sftp) sessions permitted per network connection. The default is 10. | `nil` |
| `sshd.authenticationMethods` | Specifies the authentication methods that must be successfully completed for a user to be granted access. The default is to accept any single authentication method | `nil` |
| `sshd.pubKeyAuthentication` | Specifies whether public key authentication is allowed. The default is yes. | `nil` |
| `sshd.pubKeyAcceptedKeyTypes` | Specifies the key types that will be accepted for authentication. The default value is "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,ssh-rsa". | `nil` |
| `sshd.revokedKeys` | Specifies revoked public keys file, or none to not use one. | `nil` |
| `sshd.authorizedKeysCommand` | Specifies a program to be used to look up the user's public keys. By default, no AuthorizedKeyCommand is run. | `nil` |
| `sshd.authorizedKeysCommandUser` | Specifies the user under whose account the AuthorizedKeysCommand is run. | `nil` |
| `sshd.authorizedKeysFile` | Specifies the file that contains the public keys used for user authentication. The default is ".ssh/authorized_keys .ssh/authorized_keys2" | `nil` |
| `sshd.authorizedPrincipalsFile` | Specifies a file that lists principal names that are accepted for certificate authentication. The default is to not use a principals file. | `nil` |
| `sshd.authorizedPrincipalsCommand` | Specifies a program to be used to generate the list of allowed certificate principals as per AuthorizedPrincipalsFile. By default, no AuthorizedPrincipalsCommand is run. | `nil` |
| `sshd.authorizedPrincipalsCommandUser` | Specifies the user under whose account the AuthorizedPricipalsCommand is run | `nil` |
| `sshd.authorizedKeysCommand` | Specifies a program to be used to look up the user's public keys. By default, no AuthorizedKeysCommand is run. | `nil` |
| `sshd.authorizedKeysCommandUser` | Specifies the user under whose account the AuthorizedKeysCommand is run. | `nil` |
| `sshd.hostbasedAcceptedKeyTypes` | Specifies the key types that will be accepted for hostbased authentication. The default is "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,ssh-rsa". | `nil` |
| `sshd.hostbasedAuthentication` | Specifies whether rhosts or `/etc/hosts.equiv` authentication together with successful public key client host authentication together is allowed. The default is no. | `nil` |
| `sshd.hostbasedUsesNameFromPacketOnly` | Specifies whether or not the server will attempt to perform a reverse name lookup when matching the name in the `~/.shosts`, `~/.rhosts`, and `/etc/hosts.equiv` files during HostbasedAuthentication. The default is no. | `nil` |
| `sshd.hostCertificate` | Specifies a file containing a public host certificate. The default behaviour of `sshd` is not to load any certificates. | `nil` |
| `sshd.trustedUserCaKeys` | Specifies a file containing public keys of certificate authorities that are trusted to sign user certificates for authentication, or none to not use one. | `nil` |
| `sshd.hostKeys` | Specifies a file containing a private host key used by SSH. The defaults are `/etc/ssh/ssh_host_rsa_key`, `/etc/ssh/ssh_host_ecdsa_key` and `/etc/ssh/ssh_host_ed25519_key` | `[]` |
| `sshd.hostKeyAgent` | Identifies the UNIX-domain socket used to communicate with an agent that has access to the private host keys | `nil` |
| `sshd.hostKeyAlgorithms` | Specifies the host key algorithms that the server offers. The default is "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,ssh-rsa" | `nil` |
| `sshd.ignoreRhosts` | Specifies that `.rhosts` and `.shosts` files will not be used in HostBasedAuthentication. The default is yes. | `true` |
| `sshd.ignoreUserKnownHosts` | Specifies whether `sshd` should ignore the user's `~/.ssh/known_hosts` during HostBasedAuthentication. The default it no. | `nil` |
| `sshd.IPQoS` | Specifies the IPv4 type-of-service or DSCP class for the connection. The default is lowdelay for interactive sessions and throughput for non-interactive sessions. | `nil` |
| `sshd.kdbInteractiveAuthentication` | Specifies whether to allow keyboard-interactive authentication. The default is to use whatever value ChallengeResponseAuthentication is set to (by default yes). | `nil` |
| `sshd.passwordAuthentication` | Specifies whether password authentication is allowed. The default is yes. | `false` |
| `sshd.permitEmptyPasswords` | Specifies whether the server allows login to accounts with empty password strings when password authentication is enabled. The default is no. | `false` |
| `sshd.permitOpen` | Specifies the destinations to which TCP port forwarding is permitted. By default all port forwarding requests are permitted. | `nil` |
| `sshd.challengeResponseAuthentication` | Specified whether challenge-response authentication is allowed. The default is yes. | `false` |
| `sshd.kerberosAuthentication` | Specifies whether the password provided by the user for PasswordAuthentication will be validated through the Kerberos KDC. The default is no. | `nil` |
| `sshd.kerberosGetAFSToken` | If AFS is active and the user has a Kerberos 5 TGT, attempt to acquire an AFS token before accessing the user's home directory. The default is no. | `nil` |
| `sshd.kerberosOrLocalPassword` | If password authentication through Kerberos fails then the password will be validated via any addition local mechanism. The default is yes. | `nil` |
| `sshd.kerberosTicketCleanup` | Specifies whether to automatically destroy the user's ticket cache file on logout. The default is yes. | `true` |
| `sshd.gssApiAuthentication` | Specifies whether user authentication based on GSSAPI is allowed. The default is no. | `nil` |
| `sshd.gssApiKeyExchange` | Specifies whether key exchange based on GSSAPI is allowed. The default is no. | `nil` |
| `sshd.gssApiCleanupCredentials` | Specifies whether to automatically destroy the user's credentials cache on logout. The default is yes. | `nil` |
| `sshd.gssApiStrictAcceptorCheck` | Determines whether to be strict about the identity of the GSSAPI acceptor a client authenticates against. The default is yes. | `nil` |
| `sshd.gssApiStoreCredentialsOnRekey` | Controls whether the user's GSSAPI credentials should be updated following a successful connection rekeying. The default is no. | `nil` |
| `sshd.usePam` | Enables the Pluggable Authentication Module interface. The default is no. | `nil` |
| `sshd.allowAgentForwarding` | Specifies whether `ssh-agent` forwarding is permitted. The default is to allow `ssh-agent` forwarding. | `nil` |
| `sshd.allowTcpForwarding` | Specifices whether TCP forwarding is permitted. The default is to allow all TCP forwarding. | `nil` |
| `sshd.allowStreamLocalForwarding` | Specifies whether SteamLocal (Unix-domain socket) forwarding is permitted. The default is to allow all StreamLocal forwarding. | `nil` |
| `sshd.streamLocalBindMask` | Sets the octal file creation mode mask (umask) used when creating a UNIX-domain socket file for local or remote port forwarding. The default value is 0177. | `nil` |
| `sshd.streamLocalBindUnlink` | Specifies whether to remove an existing UNIX-domain socket file for local or remote forwarding before creating a new one. The default is no. | `nil` |
| `sshd.allowGroups` | List of groups allowed to login. By default login is allowed for all groups. | `nil` |
| `sshd.allowUsers` | List of users allowed to login. By default login is allowed for all users. | `nil` |
| `sshd.denyGroups` | List of group name patterns for which login is not permitted. By default, login is allowed for all groups | `nil` |
| `sshd.denyUsers` | List of users for which login is not permitted. By default, login is allowed for all users. | `nil` |
| `sshd.disableForwarding` | Disables all forwarding features (X11, `ssh-agent`, TCP and StreamLocal). This option overrides all other forwarding-related options. | `nil` |
| `sshd.exposeAuthInfo` | Writes a temporary file containing a list of authentication methods and public credentials (e.g. keys) used to authenticate the user. the default is no. | `nil` |
| `sshd.fingerprintHash` | Specifies the has algorithm used when logging key fingerprints. The default is sha256. | `nil` |
| `sshd.forceCommand` | Forces the execution of command specified by ForceCommand, ignoring any command supplied by the client and `~/.ssh/rc` if present. The default is none. | `nil` |
| `sshd.gatewayPorts` | Specifies whether remote hosts are allowed to connect to ports forwarded for the client. The default is no. | `nil` |
| `sshd.x11Forwarding` | Specifies whether X11 forwarding is permitted. The default is no. | `nil` |
| `sshd.x11DispalyOffset` | Specifies the first display number available for `sshd`'s X11 forwarding. The default is 10. | `nil` |
| `sshd.x11UseLocalhost` | Specifies whether `sshd` should bind the X11 forwarding server to the loopback address or to the wildcard address. The default is yes. | `nil` |
| `sshd.xAuthLocation` | Speficies the full pathname of the `xauth` program, or none to not use one. The default is `/usr/bin/xauth` | `nil` |
| `sshd.permitTTY` | Specifies whether `pty` allocation is permitted. The default is yes. | `nil` |
| `sshd.permitUserRC` | Specifies whether and `~/.ssh/rc` file is executed. The default is yes. | `nil` |
| `sshd.printMotd` | Specifies whether `sshd` should print `/etc/motd` when a user logs in interactively. The default is yes. | `nil` |
| `sshd.printLastLog` | Specifies whether `sshd` should print the date and time of the last user login when a user logs in interactively. The default is yes. | `nil` |
| `sshd.tcpKeepAlive` |Specifies whether the system should send TCP keepalive messages to the other side. The default is yes. | `nil` |
| `sshd.useLogin` | Specifies whether `login` is used for interactive login sessions. The default is no. | `nil` |
| `sshd.permitUserEnvironment` | Specifies whether `~/.ssh/environment` and environment= options in `~/.ssh/authorized_keys` are processed by `sshd`. The default is no. | `nil` |
| `sshd.compression` | Specifies whether compression is enabled after the user has authenticated successfully. The default is yes. | `nil` |
| `sshd.clientAliveCountMax` | Sets the number of client alive messages which may be sent without `sshd` receiving any messages back from the client. The default is 3. | `nil` |
| `sshd.clientAliveInterval` | Sets a timeout interval in seconds after which if no data has been received from the client, `sshd` will send a message through the encrypted channel to request a response from the client. The default is 0. | `nil` |
| `sshd.useDNS` | Specifies whether `sshd` should look up the remote host name, and to check that the resolved host name for the remote IP address maps back to the very same IP address. The default is no. | `nil` |
| `sshd.debianBanner` | Specifies whether the distribution-specified extra version suffix is included during initial protocol handshake. The default is yes. | `nil` |
| `sshd.pidFile` | Specifies the file that contains the process ID of the SSH daemon, or none to not write one. The default is `/var/run/sshd.pid`. | `nil` |
| `sshd.maxStartups` | Specifies the maximum number of concurrent unauthenticated connections to the SSH daemon. The default is 10:30:100. | `nil` |
| `sshd.permitTunnel` | Specifies whether `tun` device forwarding is allowed. The default is no. | `nil` |
| `sshd.chrootDirectory` | Specifies the pathname of a directory to chroot to after authentication. The default is none. | `nil` |
| `sshd.versionAddendum` | Optionnally specifies additional test to append to the SSH protocol bassent sent by the server upon connection. The default is none. | `nil` |
| `sshd.banner` | The contents of the specified file are sent to the remote user before authentication is allowed. By default, no banner is displayed | `nil` |
| `sshd.acceptEnv.enabled` | Allow environment variables sent by the client | `true` |
| `sshd.acceptEnv.variables` | Client environment variables to copy in the sessions `environ` | `[LANG, LC_*]` |
| `sshd.subsystems.enabled` | Configures an external subsystem (e.g. file transfer daemon). By default no subsystems are defined. | `true` |
| `sshd.subsystems.systems.name` | Specifies the subsystem to enable | `sftp` |
| `sshd.subsystems.systems.value` | Specifies the subsystem command | `/usr/lib/openssh/sftp-server` |
| `sshd.matchUser.enabled` | Introduces a conditional User criteria block. | `{}` |
| `sshd.matchUser.users`: `{}` |
| `sshd.matchUser.users.name`: `""` |
| `sshd.matchUser.users.settings`: `{}` |
| `sshd.matchUser.users.settings.name`: `""` |
| `sshd.matchUser.users.settings.value`: `""` |
| `authorized_keys`: `[]` |
