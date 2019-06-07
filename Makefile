.PHONY: all build

all: build

build:
	docker build -f openssh-server/Dockerfile -t openssh-server:latest openssh-server/
