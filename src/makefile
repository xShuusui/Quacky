.PHONY: all evaluate repair

all: evaluate repair

# TODO: Check how to use -c for resource type constraints which improves performance drastically.
evaluate:
	python quacky.py -p1 ../tmp/aws_s3_bucket.process_function_bucket.json -b 100 -e -f

repair:
	python repair.py -p1 ../tmp/aws_s3_bucket.process_function_bucket.json -test ../tmp/requests.json -perm 120 -b 100 -e
