DOCKER_REGISTRY = docker.chameleoncloud.org
IMAGE_NAME = jupyterhub
DEV_TARGET = dev
RELEASE_TARGET = release
RELEASE_PLATFORM = linux/amd64
TAG_VERSION = $(shell git log -n1 --format=%h -- .)

.PHONY: pypi-publish
pypi-publish:
	@ rm -rf build dist
	python setup.py sdist bdist_wheel
	twine upload dist/*

.PHONY: hub-build-dev
hub-build-dev:
	docker build -t $(DOCKER_REGISTRY)/$(IMAGE_NAME):dev --target $(DEV_TARGET) .

.PHONY: hub-build-release
hub-build-release:
	docker build --platform $(RELEASE_PLATFORM) -t $(DOCKER_REGISTRY)/$(IMAGE_NAME):$(TAG_VERSION) --target $(RELEASE_TARGET) .

.PHONY: hub-publish-release
hub-publish:
	docker push $(DOCKER_REGISTRY)/$(IMAGE_NAME):$(TAG_VERSION)
