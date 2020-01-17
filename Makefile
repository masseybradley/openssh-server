.PHONY: all
all: build

.PHONY: build
build:
	docker run --rm -it \
		-v ${PWD}:/workspace/source \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v ${HOME}/.docker/config.json:/root/.docker/config.json:ro \
		-v ${HOME}/.skaffold:/root/.skaffold \
		-w /workspace/source \
		--entrypoint skaffold \
		--network host \
		gcr.io/k8s-skaffold/skaffold:v1.1.0 build
