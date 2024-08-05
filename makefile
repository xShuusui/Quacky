IMAGE_NAME := abc
IMAGE_TAG := latest
TARGET_DIR := /usr/src/quacky

.PHONY: all build run evaluate repair

all: build run

build:
	docker build --file Dockerfile --tag $(IMAGE_NAME):$(IMAGE_TAG) .

run:
	docker run -it --mount type=bind,source=$(PWD),target=$(TARGET_DIR) --workdir $(TARGET_DIR)/src $(IMAGE_NAME):$(IMAGE_TAG) bash
