INPUT_DIR := ../tmp
ABC_PERMISSIVENESS_BOUND := 100


# have initial assumption that perm bound >= |must-allow request|
PERMISSIVENESS_FRACTION := 0.43 #45 #0.375


FILE := aws_sqs_queue.1.json
REQUESTS := aws_sqs_queue.1.requests.json

EVALUATE_OPTIONS := --bound $(ABC_PERMISSIVENESS_BOUND) --variable #--constraints --enc
REPAIR_OPTIONS := --bound $(ABC_PERMISSIVENESS_BOUND) --permissiveness-frac $(PERMISSIVENESS_FRACTION)

.PHONY: all evaluate repair

all: evaluate repair

evaluate:
	rm -rf evaluated_output.json
	python quacky.py -p1 $(INPUT_DIR)/$(FILE) $(EVALUATE_OPTIONS)

repair:
	python repair.py -p1 $(INPUT_DIR)/$(FILE) --testcases $(INPUT_DIR)/$(REQUESTS) $(REPAIR_OPTIONS)
