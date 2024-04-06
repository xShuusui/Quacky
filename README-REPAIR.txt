This repository contains the source code and policy/request dataset for the
paper submission "Quantitative Policy Repair for Access Control on the Cloud" 

CONTENTS:

- src: We build our repair approach on top of the Quacky tool from 
the paper "Quantifying permissiveness of access control policies" written by
W Eiers, G Sankaran, A Li, E O'Mahony, B Prince, T Bultan, published at the
44th International Conference on Software Engineering (ICSE 2022). Therefore,
the entry point into our tool is located within the src folder.

- samples/repair: We augment the policy dataset from the Quacky paper (see above)
with requests. We input the policies and requests into our policy repair tool
to evaluate our repair approach. Each subfolder in this dataset folder has a 
policy and a set of requests, both in JSON.

INSTALLATION:

We installed Quacky using the documentation in its repository, located at
the following URL: https://github.com/vlab-cs-ucsb/quacky. Note that Quacky
has its own prerequisites and dependencies which we depend on transitively.

USAGE:

There are two entry points into the repair. 

1. The script 'repair.py', located in the src folder, is used
to repair a single policy subject to the given requests and command-line
options. Many command-line options are already documented in Quacky's repo.

python3 repair.py \
    -p1 <policy to repair> \
    -test <requests> \
    -perm <permissiveness bound> \
    -b 100 -e -c                     # Quacky-specific command line options

For example, a sample invocation is

python3 repair.py \
    -p1 ../samples/repair/ec2_actions_region_aws-portal/policy.json \
    -test ../samples/repair/ec2_actions_region_aws-portal/requests.json \
    -perm 60 \
    -b 100 -e -c

2. The script 'runner_single.py', also located in the src
folder, is used to repair a batch of policies. There is a subfolder called
'repair' in samples which contains such a batch of policies.

python3 runner_single.py -d repair -perm <permissiveness bound> -b 100 -e -c