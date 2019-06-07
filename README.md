# openssh-server

`openssh-server` in `docker` pre-baked with `netcat` (`ProxyCommand`'s) and `libpam-google-authenticator` (2FA).

## requirements

1. `docker`
2. `docker-compose`

Optional: `make`

## how?

In it's default configuration you can not access the container over `ssh`. This is to prevent running this image in a production environment with an insecure private/public key-pair or password.

The `ubuntu` user used for connections has no password and the default `sshd_config` for `PermitRootLogin` is `prohibit-password`. Neither users have default `authorized_keys`.

This project assumes that you have an rsa key pair in your `~/.ssh/` directory named `id_rsa` and `id_rsa.pub`.

You should extend this image with your `authorized_keys` configuration file or bind-mount the file at `/home/ubuntu/.ssh/authorized_keys`.

### build

Build the `openssh-server` using `docker`: `docker build -f openssh-server/Dockerfile -t openssh-server openssh-server`

Alternatively, build the image using `make` (default target: `make build`).

### runtime

Run the container service using `docker-compose`: `docker-compose up -d` or using the `docker` command line:
```
docker run -d \
    --restart always
    --name openssh
    --hostname openssh.example.com
    -v ${HOME}/.ssh/id_rsa.pub:/home/ubuntu/.ssh/authorized_keys:ro
    -v openssh:/etc/ssh
    --cap-add SETUID
    --cap-add SETGID
    --cap-add CHOWN
    --cap-add SYS_CHROOT
    -p 2222:22
    openssh-server
```

## why?

The `openssh-server` image can be configured for various use cases:
- `ssh` bastion server configuration using `ProxyCommand`
- `vpn` tunneling over `ssh`
- `ssh` as a `socks5` proxy
- `script`'d user sessions
- `tick` script `ssh` authentication auditing
- `ssh` with 2 factor authentication
- using `ssh`'s force command
- `sftp` guide
- `ssh` load balancing using `nginx` stream
- `ssh` honeycomb
