# Repair single AWS IAM policies.

import argparse as ap
from datetime import datetime
import os
import math
from utils.Shell import Shell

parser = ap.ArgumentParser(description = 'Repair AWS IAM policies')
parser.add_argument('-d', '--dir', help = 'Policy Directory', required = True)
parser.add_argument('-v', '--verbose', help = 'Verbose', required = False, action = 'store_true')
parser.add_argument('-e', '--enc', help = 'use action encoding', required = False, action = 'store_true')
parser.add_argument('-c', '--constraints', help = 'use resource type constraints', required = False, action = 'store_true')  
parser.add_argument('-perm', '--permissiveness-frac', help = 'permissiveness fraction', required = True)
parser.add_argument('-b', '--bound', help = 'Bound', required = True)
args = parser.parse_args()

print('path,policy,success,initial permissiveness,permissiveness bound,permissiveness,iters,enum_point_permissiveness,enum_iters,time,abc time,abc calls,z3 time,z3 calls')

# Stats
NSUCCESS = 0
NFAILURE = 0 
NERROR = 0
NENUM = 0
SUM_ITERS = 0
SUM_TOTAL_TIME = 0.0
SUM_ABC_TIME = 0.0
SUM_ABC_NCALLS = 0
SUM_Z3_TIME = 0.0
SUM_Z3_NCALLS = 0

# Get timestamp
timestamp = round(datetime.now().timestamp())

#Copy examples to results directory
single_policy_dir = os.fsencode(f'../samples/{args.dir}/')

def get_repair_result_lines(path, policy, out, err):
    global NSUCCESS
    global NFAILURE
    global NERROR
    global NENUM
    global SUM_ITERS
    global SUM_TOTAL_TIME
    global SUM_ABC_TIME
    global SUM_ABC_NCALLS
    global SUM_Z3_TIME
    global SUM_Z3_NCALLS

    out = str(out).rstrip().split('\n')
    if out[-1] != 'done':
        print(','.join([path, policy] + ['?'] * 9))
        NERROR += 1

        return False

    success = out[-13].split(': ')[1]
    if success == 'True':
        NSUCCESS += 1
    else:
        NFAILURE += 1

    initial_permissiveness = out[-12].split(': ')[1]
    permissiveness_bound = out[-11].split(': ')[1]
    permissiveness = out[-10].split(': ')[1]

    iters = out[-9].split(': ')[1]
    SUM_ITERS += int(iters)

    enum_permissiveness = out[-8].split(': ')[1]
    enum_iters = out[-7].split(': ')[1]
    if int(enum_iters) > 0:
        NENUM += 1
    SUM_ITERS += int(enum_iters)

    total_time = out[-6].split(': ')[1]
    SUM_TOTAL_TIME += float(total_time)

    abc_time = out[-5].split(': ')[1]
    SUM_ABC_TIME += float(abc_time)

    abc_ncalls = out[-4].split(': ')[1]
    SUM_ABC_NCALLS += int(abc_ncalls)

    z3_time = out[-3].split(': ')[1]
    SUM_Z3_TIME += float(z3_time)

    z3_ncalls = out[-2].split(': ')[1]
    SUM_Z3_NCALLS += int(z3_ncalls)

    print(','.join([path, 
                    policy,
                    success,
                    initial_permissiveness,
                    permissiveness_bound,
                    permissiveness,
                    iters,
                    enum_permissiveness,
                    enum_iters,
                    total_time,
                    abc_time,
                    abc_ncalls,
                    z3_time,
                    z3_ncalls]))
    
    return True

def call_repair(path, policy):
    shell = Shell()

    #Call policy repair
    cmd =  f'python3 repair.py -p1 {path}/{policy} -test {path}/requests.json'
    cmd += f' -perm {args.permissiveness_frac} -b {args.bound}'
    if args.constraints:
        cmd += ' -c'
    if args.enc:
        cmd += ' -e'

    out, err = shell.runcmd(cmd)
    if args.verbose:
        print(out, err)

    # Get results
    if not get_repair_result_lines(path, policy, out, err):
        return

    #Write results to files
    with open(f'out_{args.permissiveness_frac}_{args.bound}.txt', 'w') as outfile:
        outfile.write(str(out))
    
    with open(f'err_{args.permissiveness_frac}_{args.bound}.txt', 'w') as errfile:
        errfile.write(str(err))

    #Store result files and repaired policy
    out, err = shell.rmrdir(f"{path}/results_{policy.replace('.json', '')}_{timestamp}")
    if args.verbose:
        print(out, err)

    out, err = shell.mkdir(f"{path}/results_{policy.replace('.json', '')}_{timestamp}")
    if args.verbose:
        print(out, err)

    out, err = shell.mv('repaired.json', 
                        f"{path}/results_{policy.replace('.json', '')}_{timestamp}")
    if args.verbose:
        print(out, err)

    out, err = shell.mv(f'out_{args.permissiveness_frac}_{args.bound}.txt', 
                        f"{path}/results_{policy.replace('.json', '')}_{timestamp}")
    if args.verbose:
        print(out, err)

    out, err = shell.mv(f'err_{args.permissiveness_frac}_{args.bound}.txt', 
                        f"{path}/results_{policy.replace('.json', '')}_{timestamp}")
    if args.verbose:
        print(out, err)

#Iterate through all policies within directory and perform check.
for dir in os.listdir(single_policy_dir):
    path = os.fsdecode(single_policy_dir) + os.fsdecode(dir)

    for file in os.listdir(path):
        policy = os.fsdecode(file)

        if not policy.endswith('.json'):
            continue
            
        if policy.startswith('requests'):
            continue
        
        call_repair(path, policy)

#Print stats
print(f'''-----
repair outcomes:
    success:    {NSUCCESS}
    failure:    {NFAILURE}
    error:      {NERROR}
    total:      {NSUCCESS + NFAILURE + NERROR} 
    ---
    w/o enum:   {NSUCCESS - NENUM}
    enumerated: {NENUM}
    % w/o enum: {float(NSUCCESS - NENUM)/float(NSUCCESS)}
    % enum    : {float(NENUM)/float(NSUCCESS)}

iterations:
    sum: {SUM_ITERS}
    avg: {SUM_ITERS / (NSUCCESS + NFAILURE)}
total time (s):
    sum: {SUM_TOTAL_TIME}
    avg: {SUM_TOTAL_TIME / (NSUCCESS + NFAILURE)}
abc time (s):
    sum: {SUM_ABC_TIME}
    avg: {SUM_ABC_TIME / (NSUCCESS + NFAILURE)}
abc calls:
    sum: {SUM_ABC_NCALLS}
    avg: {SUM_ABC_NCALLS / (NSUCCESS + NFAILURE)}
z3 time (s):
    sum: {SUM_Z3_TIME}
    avg: {SUM_Z3_TIME / (NSUCCESS + NFAILURE)}
z3 calls:
    sum: {SUM_Z3_NCALLS}
    avg: {SUM_Z3_NCALLS / (NSUCCESS + NFAILURE)}
''')
