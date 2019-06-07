# syntax = docker/dockerfile:experimental
FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive

EXPOSE 22

VOLUME ["/etc/ssh"]
VOLUME ["/var/run/sshd"]

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        netcat \
        locales \
        libpam-google-authenticator && \
    rm -rf /var/lib/apt/cache

RUN dpkg-reconfigure openssh-server

RUN groupadd -g 1000 ubuntu && \
    useradd -u 1000 -g ubuntu -d /home/ubuntu -m -s /bin/bash -k /etc/skel ubuntu

RUN mkdir /home/ubuntu/.ssh && \
    chmod 700 /home/ubuntu/.ssh && \
    chown -R ubuntu:ubuntu /home/ubuntu/.ssh

ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e"]
