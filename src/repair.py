# use CONSTRAINTS, but not ENCODING!
# use SMT-LIB syntax!
# TODO: support encoding

# repair-specific imports
from repair_transform import *
from repair_trie import *
from z3 import *

# Quacky imports
from aws_constraints import aws_action_encoding
from expressions import regexpr
from frontend import *
from translator import call_translator
from utilities import *
from utils.Shell import Shell

import copy

# other package imports
import argparse as ap
import itertools
import json
import math
import sys
import time
import sys




shell = Shell()

# globals for policy, SMT formula, set of requests
POLICY = None
FORMULA = ''
TESTCASES = None

# globals to keep track of refinement
REFINED_STATEMENT_ID = 0
REFINED_STATEMENT_IDS = []
REFINED_STATEMENT_RESOURCES_IDS = {}
REFINED_STATEMENT_CONDITIONS_IDS = {}

# globals for statistics
ABC_TIME = 0.0
ABC_NCALLS = 0
ABC_NSAT = 0

Z3_TIME = 0.0
Z3_NCALLS = 0
Z3_NSAT = 0

FN_TIME = dict()


MAIN_REPAIR_CALL_TIME = 0.0
GET_CANDIDATES_TOTAL_TIME = 0.0
GET_NEW_POLICY_TIME = 0.0
GET_NEW_POLICY_ENUMERATED_TIME = 0.0
CALL_TRANSLATOR_TIME = 0.0
SOLVER_TIME = 0.0
COUNTER_TIME = 0.0



def get_results(fname, args, shell, timeout = None):
    """
    Run ABC and get results.
    Args:
        fname ([str): file name
        bound (str): bound
        timeout (int): timeout, in seconds
    Returns:
        dict: results
    """

    global COUNTER_TIME

    cmd = ''
    
    if timeout:
        cmd += 'timeout -k {0}s {0}s '.format(timeout)
    
    cmd += f'abc -i {fname}'
    cmd += f' -bs {args.bound}'
    cmd += ' --precise --count-tuple-variables action,resource -v 0'


    start = time.time()
    out, err = shell.runcmd(cmd)
    end = time.time()
    COUNTER_TIME += (end - start)

    # Parse ABC output
    results = get_abc_result_line(out, err)

    return results

def update_abc_stats(results):
    global ABC_NCALLS
    global ABC_NSAT
    global ABC_TIME

    ABC_TIME += float(results['solve_time']) / 1000
    ABC_NCALLS += 1

    if results['is_sat'] == 'sat':
        ABC_TIME += float(results['count_time']) / 1000
        ABC_NSAT += 1

# more readable than profiling
# just looks at top-level functions
def update_fn_time(t):
    global FN_TIME

    caller = sys._getframe(1).f_code.co_name
    
    if caller not in FN_TIME:
        FN_TIME[caller] = t
    else:
        FN_TIME[caller] += t

# returns true if there is at least one unrefined statement
def has_unrefined_statements():
    for i in range(len(POLICY['Statement'])):
        if POLICY['Statement'][i]['__sid'] not in REFINED_STATEMENT_IDS and POLICY['Statement'][i]['Effect'] != 'Deny':
            return True

    return False

# checks if the statement has already been refined
def is_statement_refined(i):
    return POLICY['Statement'][i]['__sid'] in REFINED_STATEMENT_IDS

# checks if the resource in the given statement is refined or not
def is_statement_resource_refined(statement, resource):
    return (resource in REFINED_STATEMENT_RESOURCES_IDS[statement['__sid']])

# mark resources in statement as refined
# if statement has only refined resources, then mark statement as refined
def mark_statement_resources_as_refined(i, resources):
    global REFINED_STATEMENT_RESOURCES_IDS
    global POLICY
    global REFINED_STATEMENT_IDS

    __ssid = POLICY['Statement'][i]['__sid']
    REFINED_STATEMENT_RESOURCES_IDS[__ssid] += resources

    # check if statement has any unrefined resources
    has_unrefined_resource = False
    for resource in POLICY['Statement'][i]['Resource']:
        if resource not in REFINED_STATEMENT_RESOURCES_IDS[__ssid]:
            has_unrefined_resource = True
            break

    # if statement has no unrefined resources, mark statement as refined
    if not has_unrefined_resource:
        REFINED_STATEMENT_IDS.append(__ssid)

# TODO
def is_statement_condition_refined():
    pass

# TODO
def mark_statement_conditions_as_refined():
    pass





# this just looks at action/resource pairs
# TODO: add conditions to candidates...but how?
# we probably shouldn't include them in the cartesian product
# or else the cardinality of that product will blow up.
# TODO: if we change the candidate data structure, change the
# lambda function in the sort
def get_candidates_helper(args):
    # fn_start_time = time.time()

    actions = set()
    resources = set()
    candidates = {}

    for statement in POLICY['Statement']:
        for action in statement['Action']:
            actions.add(action.lower())
        
        for resource in statement['Resource']:
            # only unrefined resources can be candidates
            # note that if a statement has no unrefined resources,
            # this program point should never be reached for that statement
            if not is_statement_resource_refined(statement, resource):
                resources.add(resource)
    
    for action, resource in itertools.product(actions, resources):

        # short circuit unary/single requests
        if "*" not in resource and "?" not in resource:
            candidates[(action,resource)] = {'count': 0.0}
            continue

        # augment formula, fix the action ("fix" != "repair")
        # TODO: augment with test cases as well?
        if args.enc:
            smt = aws_action_encoding(action, args.smt_lib) 
        else:
            action_pattern = regexpr(action, False)
            smt = f'(in action /{action_pattern}/)' 
        
        resource_pattern = regexpr(resource, False)
        formula = FORMULA.replace(
            f'(assert p0.allows)\n',
            f'(assert (and {smt} ' +
            f'(in resource /{resource_pattern}/)))\n' +
            f'(assert p0.allows)\n'
        )

        f = open('output_temp_1.smt2', 'w')
        f.write(formula)
        f.close()

        # add action to candidates

        results = get_results('output_temp_1.smt2', args, shell)
        update_abc_stats(results)

        if results['is_sat'] == 'sat':
            count = math.log(int(results['count']),256)
            candidates[(action, resource)] = {'count': count}

    # get most permissive action/resource pair as candidate
    sorted_candidates = sorted(
        candidates.items(), 
        key = lambda item: item[1]['count'], 
        reverse = True)

    # fn_end_time = time.time()
    # update_fn_time(fn_end_time - fn_start_time)
    
    return sorted_candidates

# find most overly permissive statement
# assume that if a combination of statements
# yields a high permissiveness, then so does
# at least one of those statements.
# the repair candidates can be found within
# that statement, shrinking the search space.
def get_candidates(args, k=1):
    # fn_start_time = time.time()

    global POLICY

    global CALL_TRANSLATOR_TIME

    # statement candidates
    statement_candidates = {}

    for i in range(len(POLICY['Statement'])):
        statement = POLICY['Statement'][i]

        # candidate statement must not be already refined (STOPPING CONDITION)
        if is_statement_refined(i):
            print(f"STATEMENT {i} IS REFINED")
            continue

        # back up stuff
        # this is somewhat convoluted, but
        # it prevents me from copying over
        # the full translation logic.
        temp_policy = copy.deepcopy(POLICY)
        temp_args_policy1 = args.policy1
        temp_args_output = args.output
        
        # create policy from statement
        POLICY = {'Statement': [statement]}
        args.policy1 = 'policy_temp.json'
        args.output = 'output_temp'

        # write policy to file
        f = open('policy_temp.json', 'w')
        f.write(json.dumps(POLICY, indent=4))
        f.close()

        # translate policy
        start = time.time()
        call_translator(args)
        end = time.time()
        CALL_TRANSLATOR_TIME += (end - start)

        # get model count
        results = get_results('output_temp_1.smt2', args, shell)
        update_abc_stats(results)

        if results['is_sat'] == 'sat':
            count = math.log(int(results['count']),256)
            statement_candidates[i] = {'count': count}

        # restore
        POLICY = copy.deepcopy(temp_policy)
        args.policy1 = temp_args_policy1
        args.output = temp_args_output
    
    # get most permissive statement as candidate
    sorted_statement_candidates = sorted(
        statement_candidates.items(), 
        key = lambda item: item[1]['count'], 
        reverse = True)
    print(f"k = {k}")
    print(f"sorted_statement_candidates length = {len(sorted_statement_candidates)}")
    print(f'{sorted_statement_candidates}')
    
    i = sorted_statement_candidates[k - 1][0]
    statement = POLICY['Statement'][i]
    
    # backup
    temp_policy = copy.deepcopy(POLICY)
    
    # run get_candidates_2
    POLICY = {'Statement': [statement]}
    candidates = get_candidates_helper(args)
    print(f'candidates: {candidates}')

    # restore
    POLICY = copy.deepcopy(temp_policy)

    # fn_end_time = time.time()
    # update_fn_time(fn_end_time - fn_start_time)

    return i, candidates

# retuns list of failed test cases
def check_testcases():
    # fn_start_time = time.time()

    global POLICY
    global Z3_TIME
    global Z3_NCALLS
    global Z3_NSAT

    global CALL_TRANSLATOR_TIME
    global SOLVER_TIME

    if len(POLICY['Statement']) == 0:
      print("empty policy")
      return TESTCASES

    # call z3 on the policy + test cases
    # collect all test cases which fail
    # return those that fail
    failed_testcases = []
    
    for i in range(len(TESTCASES)):
        temp_policy = copy.deepcopy(POLICY)
        temp_args_policy1 = args.policy1
        temp_args_output = args.output
        temp_args_smt_lib = args.smt_lib
        
        args.policy1 = 'policy_temp.json'
        args.output = 'output_temp'
        args.smt_lib = True

        # write policy to file
        f = open('policy_temp.json', 'w')
        f.write(json.dumps(POLICY, indent=4))
        f.close()

        # translate policy
        start = time.time()
        call_translator(args)
        end = time.time()
        CALL_TRANSLATOR_TIME += (end - start)

        f = open('output_temp_1.smt2','r')
        lines = f.readlines()
        lines = lines[:-2]    
        f.close()
    
        f = open('output_temp_1.smt2','w')
        f.write("".join(lines))
        f.write(f"(assert (= resource \"{TESTCASES[i]['Resource']}\"))\n")
        
        if args.enc:
            smt = aws_action_encoding(TESTCASES[i]['Action'].lower(), args.smt_lib)
        else:
            smt = f"(= action \"{TESTCASES[i]['Action'].lower()}\")"
            
        f.write(f"(assert {smt})\n")
        f.write("(check-sat)\n")
        f.write("(get-model)\n")
        f.close()

        # call z3 and get satisfiability
        start_time = time.time()
        
        ctx = Context()
        s = Solver(ctx = ctx)
        s.add(parse_smt2_file('output_temp_1.smt2', ctx = ctx))
        is_sat = (s.check() == sat)
        
        end_time = time.time()
        SOLVER_TIME += (end_time - start_time)

        if not is_sat:
            failed_testcases.append(TESTCASES[i])
        else:
            Z3_NSAT += 1

        Z3_TIME += end_time - start_time 
        Z3_NCALLS += 1
        
        # restore
        POLICY = copy.deepcopy(temp_policy)
        args.policy1 = temp_args_policy1
        args.output = temp_args_output
        args.smt_lib = temp_args_smt_lib

    # fn_end_time = time.time()
    # update_fn_time(fn_end_time - fn_start_time)

    return failed_testcases

'''
send list of failed test cases to ABC to get one or more simplified regexes characterizing the test cases

ABC requires a constraint file in smt2lib format, so we need to create that first
The constraint will simply be the disjunction of all the failed testcases
'''
def refine_permissiveness(failed_testcases):
    # fn_start_time = time.time()

    global COUNTER_TIME

    length_param_alpha = 0; # hard coded but can be changed
    depth_param_omega = 3; # hard coded but can be changed

    body = ''
    disjunction = ''
    reg_out_file = 'output_reg.txt'

    for testcase in failed_testcases:
        for k, v in testcase.items():
            if k == 'Resource':
                disjunction += f"(= resource \"{testcase['Resource']}\")\n"

    body += declare('resource', 'String')
    body += '(assert (or \n' + disjunction + '))\n'
    body += '(check-sat)'

    file = open('output_1.smt2', 'w')
    file.write(body)
    file.close()

    # call ABC on constraint file
    cmd = f'abc -i output_1.smt2'
    cmd += f' -bs 5'
    cmd += f' --precise --count-tuple --dfa-to-re resource {reg_out_file} {length_param_alpha} {depth_param_omega} -v 0'
    
    start = time.time()
    out, err = shell.runcmd(cmd)
    end = time.time()
    COUNTER_TIME += (end - start)
    results = get_abc_result_line(out, err)
    update_abc_stats(results)

    with open(reg_out_file) as f:
        lines = [line.rstrip() for line in f]

    refined_resources = lines
    refined_conditions = []

    # fn_end_time = time.time()
    # update_fn_time(fn_end_time - fn_start_time)

    return refined_resources, refined_conditions

def get_new_policy(i, candidates, current_permissiveness, args):
    # fn_start_time = time.time()

    global POLICY

    global CALL_TRANSLATOR_TIME

    # just look at one candidate action/resource pair
    # remove it then check test cases
    # if pass test cases, we are OK - return and continue main repair loop
    # otherwise, put action back, refine resource using widening/trie
    # flag action/resource pair in statement so that it wont be touched again (end condition)
    candidate, count = candidates[0]

    if "*" not in candidate[1] and "?" not in candidate[1]:
        print(f"candidate resource ({candidate[1]}) will not reduce permissiveness; short circuiting")
        mark_statement_resources_as_refined(i,[candidate[1]])
        return

    temp_policy = copy.deepcopy(POLICY)

    # remove action/resource pair in statement
    # this is slightly messy because of casing
    # new_actions = [action
    #     for action in POLICY['Statement'][i]['Action']
    #     if action.lower() != candidate[0]
    # ]
    new_actions = POLICY['Statement'][i]['Action']

    # if statement no longer has an action or resource,
    # remove it. otherwise, update it.
    statement_deleted = False
    if len(new_actions) == 0:
        del POLICY['Statement'][i]
        statement_deleted = True
    elif len(POLICY['Statement'][i]['Resource']) == 1:
        del POLICY['Statement'][i]
        statement_deleted = True
    else:
        POLICY['Statement'][i]['Action'] = new_actions
        POLICY['Statement'][i]['Resource'].remove(candidate[1])

    # make sure that policy satisfies test cases
    # check_testcases will return which test cases fail
    # refine permissiveness by adding a new resource which
    # is the widening of the failed test cases
    # NOTE: in the worst cases we could just add new statements for
    #       each failed test case (enumeration).
    failed_testcases = check_testcases()

    if len(failed_testcases) > 0:
        refined_resources, refined_conditions = refine_permissiveness(failed_testcases)
        # restore policy
        POLICY = copy.deepcopy(temp_policy)

        # remove resource and add new refined resources
        POLICY['Statement'][i]['Resource'].remove(candidate[1])
        POLICY['Statement'][i]['Resource'] += (refined_resources)

        # Check if new policy is less permissive. if not, revert back and THEN
        # mark statement resources as refined (in this case, the removed candidate)
        # new_permissiveness = get_policy_permissiveness(POLICY)
        
        # write new policy to file
        f = open(REPAIRED_FILENAME, 'w')
        f.write(json.dumps(POLICY, indent=4))
        f.close()

        # get formula
        start = time.time()
        call_translator(args)
        end = time.time()
        CALL_TRANSLATOR_TIME += (end - start)
        FORMULA = open('output_1.smt2', 'r').read()

        # get model count
        results = get_results('output_1.smt2', args, shell)
        if results['is_sat'] == 'unsat':
            sys.exit("bad")
        
        new_permissiveness = math.log(int(results['count']),256)
        
        if new_permissiveness >= current_permissiveness - 0.01: # the -1 is the threshold changing the policy
            print("NEW PERMISSIVENESS NOT GOOD< ROLLING BACK")
            print(f'Current permissiveness: {current_permissiveness}')
            print(f'New permissiveness    : {new_permissiveness}')
            print(f'Candidate: {candidate}')
            print(f"Attempted policy: {json.dumps(POLICY, indent=4)}")
            POLICY = copy.deepcopy(temp_policy)
            print(f"Reverted back to old policy: {json.dumps(POLICY, indent=4)}")
            mark_statement_resources_as_refined(i, [candidate[1]])
            print(f'Marking {i}, {[candidate[1]]} as refined')
            #input()
        # TODO: remove condition value and add new refined condition values
    elif not statement_deleted:
        refined = True
        for res in POLICY['Statement'][i]['Resource']:
            if not is_statement_resource_refined(POLICY['Statement'][i],res):
                refined = False

        if refined:
            mark_statement_resources_as_refined(i, [])

        print(f'statement refined? {refined}')
        print(f'is_statement_refined()? {is_statement_refined(i)}')
    else:
        print(f'statement DELETED')
    print(f'AT END OF GET NEW POLICY')

def get_new_policy_enumerated(i, candidates):
    # fn_start_time = time.time()

    global POLICY

    # just look at one candidate action/resource pair
    candidate, count = candidates[0]
    temp_policy = copy.deepcopy(POLICY)

    # remove action/resource pair in statement
    # this is slightly messy because of casing
    # new_actions = [action
    #     for action in POLICY['Statement'][i]['Action']
    #     if action.lower() != candidate[0]
    # ]
    new_actions = POLICY['Statement'][i]['Action']

    # if statement no longer has an action or resource,
    # remove it. otherwise, update it.
    if len(new_actions) == 0:
        del POLICY['Statement'][i]
    elif len(POLICY['Statement'][i]['Resource']) == 1:
        del POLICY['Statement'][i]
    else:
        POLICY['Statement'][i]['Action'] = new_actions
        POLICY['Statement'][i]['Resource'].remove(candidate[1])

    # make sure that policy satisfies test cases
    # if it does not, then replace resource with enumeration of resources
    failed_testcases = check_testcases()

    if len(failed_testcases) > 0:

        # restore policy but remove action/resource pair
        # this is easy hack since we may have removed the statement if
        # the removal of an action/resource caused it to be empty
        # NOTE: we use new_actions variable created above to account for lowercase/uppercase/etc actions
        POLICY = copy.deepcopy(temp_policy)
        # POLICY['Statement'][i]['Action'] = new_actions
        POLICY['Statement'][i]['Resource'].remove(candidate[1])
        
        print(f"old UN ENUMERATED policy: {json.dumps(POLICY, indent=4)}")

        # failed_testcases is list of action,resource pairs
        # since removed action could be something like s3:*,
        # actions in failed_testcases can differ; must account for this
        for testcase in failed_testcases:
            for k, v in testcase.items():
                # dont duplicate existing action/resources
                if k == 'Resource' and v not in POLICY['Statement'][i]['Resource']:
                    POLICY['Statement'][i]['Resource'].append(v)
                    mark_statement_resources_as_refined(i, [v])
                # elif k == 'Action' and v not in POLICY['Statement'][i]['Action']:
                #     POLICY['Statement'][i]['Action'].append(v)
                # elif k == 'Action':
                #     continue
                # else:
                #     print(v not in POLICY['Statement'][i]['Action'])
                #     print(POLICY['Statement'][i]['Action'])

                #     print(v not in POLICY['Statement'][i]['Resource'])
                #     print(POLICY['Statement'][i]['Resource'])
                    
                #     sys.exit(f"failed testcase has element other than action: {k}, {v}")

                # mark each enumerated resources as refined
                # mark_statement_resources_as_refined(i, [v])
                    
    print('NEW ENUMERATED POLICY:')
    print(f"{json.dumps(POLICY, indent=4)}")
    # input()
    # fn_end_time = time.time()
    # update_fn_time(fn_end_time - fn_start_time)

# def get_policy_permissiveness(policy, policy_filename='policy_temp.json'):
#     global FORMULA

#     f = open(policy_filename, 'w')
#     f.write(json.dumps(policy, indent=4))
#     f.close()

#     # get formula
#     call_translator(args)
#     FORMULA = open('output_1.smt2', 'r').read()

#     # get model count
#     results = get_results('output_1.smt2', args, shell)
#     update_abc_stats(results)

#     if len(POLICY['Statement']) == 0:
#         permissiveness = -1
#     elif results['is_sat'] == 'unsat':
#         permissiveness = -1
#     elif results['is_sat'] == 'sat':
#         permissiveness = math.log(int(results['count']),256)

#     return permissiveness

def repair(args):
    # fn_start_time = time.time()

    global POLICY
    global FORMULA
    global TESTCASES

    global REFINED_STATEMENT_ID
    global REFINED_STATEMENT_IDS
    global REFINED_STATEMENT_RESOURCES_IDS
    global REFINED_STATEMENT_CONDITIONS_IDS

    global CALL_TRANSLATOR_TIME
    global GET_CANDIDATES_TOTAL_TIME
    global GET_NEW_POLICY_TIME
    global GET_NEW_POLICY_ENUMERATED_TIME

    global REPAIRED_FILENAME

    # start timer
    start_time = time.time()

    # get policy
    original_filename = args.policy1.rsplit('.json', 1)[0]
    REPAIRED_FILENAME = f'{original_filename}.repaired.json'

    out, err = shell.cp(args.policy1, REPAIRED_FILENAME)
    args.policy1 = REPAIRED_FILENAME

    POLICY = json.loads(open(args.policy1, 'r').read())
    
    if 'Not' in json.dumps(POLICY):
        POLICY = transform_policy(POLICY)

        #print(f'transformed policy: {json.dumps(POLICY, indent=4)}\n')

    POLICY = sanitize_and_wrap(POLICY)
    
    # add internal id to each statement for stopping condition
    # add internal id to each resource within statement
    for i in range(len(POLICY['Statement'])):
        POLICY['Statement'][i]['__sid'] = REFINED_STATEMENT_ID
        REFINED_STATEMENT_RESOURCES_IDS[REFINED_STATEMENT_ID] = []
        REFINED_STATEMENT_CONDITIONS_IDS[REFINED_STATEMENT_ID] = {} # TODO: check this
        REFINED_STATEMENT_ID += 1

    # get formula
    start = time.time()
    call_translator(args)
    end = time.time()
    CALL_TRANSLATOR_TIME += (end - start)
    FORMULA = open('output_1.smt2', 'r').read()

    # get testcases
    TESTCASES = json.loads(open(args.testcases, 'r').read())

    # get model count
    results = get_results('output_1.smt2', args, shell)
    update_abc_stats(results)
    
    if results['is_sat'] == 'sat':
        print("SAT")
        permissiveness = math.log(int(results['count']),256)
    else:
        print("UNSAT")
        permissiveness = -1

    # calculate permissiveness bound, or the end goal
    # goal = frac * permissiveness
    # log(goal) = log(frac * permissiveness) 
    #           = log(frac) + log(permissiveness)
    initial_permissiveness = permissiveness

    # if initial_permissiveness <= 0:
    #     permissiveness_bound = 0  
    # else: 
    #     permissiveness_bound = math.log(float(args.permissiveness_frac),2) + initial_permissiveness


    # bounds are given as log256
    permissiveness_bound = float(args.permissiveness_frac)

    # precondition that permissiveness bound must be at least the nubmer of requests in must-allow set
    if 256 ** permissiveness_bound < float(len(TESTCASES)):
        sys.exit("Error: permissiveness bound is greater than number of test cases")

    iters = 0
    enum_iters = 0

    while permissiveness > permissiveness_bound and has_unrefined_statements():
        # note: the actual repair for this one should
        # be to remove the (action, resource) combo
        # from the statement itself. Otherwise, the
        # same statement will keep coming up as the
        # candidate.
        start = time.time()
        i, candidates = get_candidates(args)
        end = time.time()
        GET_CANDIDATES_TOTAL_TIME += (end - start)

        # get new policy
        start = time.time()
        get_new_policy(i, candidates, permissiveness, args)
        end = time.time()
        GET_NEW_POLICY_TIME += (end - start)

        # permissiveness = get_policy_permissiveness(POLICY, 'repaired.json')
        
        # write new policy to file
        f = open(REPAIRED_FILENAME, 'w')
        f.write(json.dumps(POLICY, indent=4))
        f.close()

        # get formula
        start = time.time()
        call_translator(args)
        end = time.time()
        CALL_TRANSLATOR_TIME += (end - start)
        FORMULA = open('output_1.smt2', 'r').read()

        # get model count
        results = get_results('output_1.smt2', args, shell)
        update_abc_stats(results)

        if len(POLICY['Statement']) == 0:
            permissiveness = -1
        elif results['is_sat'] == 'unsat':
            permissiveness = -1
        elif results['is_sat'] == 'sat':
            permissiveness = math.log(int(results['count']),256)
            iters += 1

        # print iteration info
        print(f'===== iteration: {iters} =====')
        print(f'statement: {i}')
        print(f'candidates:')

        for candidate in candidates:
            print(f"\t{candidate[0]}: {candidate[1]['count']}")

        print(f"policy: {json.dumps(POLICY, indent=4)}")
        print(f'permissiveness: {permissiveness}')
        print()

    enum_point_permissiveness = permissiveness

    # #TODO: check if permissiveness bound was reached. if not, then enumeration strat
    if permissiveness > permissiveness_bound:
        # repeat repair process using enumeration strat, with all stateent/resources being unrefined
        # this is a cheap hack due to how refinment checking is implemented
        REFINED_STATEMENT_ID = 0
        REFINED_STATEMENT_IDS = []
        REFINED_STATEMENT_RESOURCES_IDS = {}
        REFINED_STATEMENT_CONDITIONS_IDS = {}
        for i in range(len(POLICY['Statement'])):
            POLICY['Statement'][i]['__sid'] = REFINED_STATEMENT_ID
            REFINED_STATEMENT_RESOURCES_IDS[REFINED_STATEMENT_ID] = []
            REFINED_STATEMENT_CONDITIONS_IDS[REFINED_STATEMENT_ID] = {} # TODO: check this
            REFINED_STATEMENT_ID += 1

        # print("HERE!")
        # print(has_unrefined_statements())

        # same approach as before but no resource/char refinement
        # we remove an action,resource pair just like before
        # but instead of creating a resrouce characterization, we just enunerate the denied reuqests
        while permissiveness > permissiveness_bound and has_unrefined_statements():
            start = time.time()
            i, candidates = get_candidates(args)
            end = time.time()
            GET_CANDIDATES_TOTAL_TIME += (end - start)

            # get new policy
            start = time.time()
            get_new_policy_enumerated(i, candidates)
            end = time.time()
            GET_NEW_POLICY_ENUMERATED_TIME += (end - start)
            
            # permissiveness = get_policy_permissiveness(POLICY, 'repaired.json')
            # if permissiveness < 0:
            #     print('UNSAT')
            #     break;
            # else:
            #     enum_iters += 1
            
            # write new policy to file
            f = open(REPAIRED_FILENAME, 'w')
            f.write(json.dumps(POLICY, indent=4))
            f.close()

            # get formula
            start = time.time()
            call_translator(args)
            end = time.time()
            CALL_TRANSLATOR_TIME += (end - start)
            FORMULA = open('output_1.smt2', 'r').read()

            # get model count
            results = get_results('output_1.smt2', args, shell)
            update_abc_stats(results)

            if len(POLICY['Statement']) == 0:
                permissiveness = -1
            elif results['is_sat'] == 'unsat':
                permissiveness = -1
            elif results['is_sat'] == 'sat':
                permissiveness = math.log(int(results['count']),256)
                enum_iters += 1

            # print enum iteration info
            print(f'===== ENUM iteration: {enum_iters} =====')
            print(f'statement: {i}')
            print(f'candidates:')

            for candidate in candidates:
                print(f"\t{candidate[0]}: {candidate[1]['count']}")

            print(f"policy: {json.dumps(POLICY, indent=4)}")
            print(f'permissiveness: {permissiveness}')
            print()
        
    # have initial assumption that perm bound >= |must-allow request|
    if permissiveness > permissiveness_bound:
        sys.exit("Fatal error: permissiveness bound cannot be met with given request set.")



    # clean up temp files
    out, err = shell.rm('policy_temp.json')
    out, err = shell.rm('output_temp_1.smt2')

    # end timer
    end_time = time.time()

    # fn_end_time = time.time()
    # update_fn_time(fn_end_time - fn_start_time)

    # print(FN_TIME)

    # print some stats
    print(f'permissiveness bound met: {permissiveness < permissiveness_bound}')
    print(f'initial permissiveness: {initial_permissiveness}')
    print(f'permissiveness goal: {permissiveness_bound}')
    print(f'permissiveness: {permissiveness}')
    print(f'iterations: {iters}')
    print(f'enum_point_permissiveness: {enum_point_permissiveness}')
    print(f'enum_iterations: {enum_iters}')
    print(f'total time (s): {end_time - start_time}')
    print(f'time spent in ABC (s): {ABC_TIME}')
    print(f'# calls to ABC: {ABC_NCALLS}')
    print(f'time spent in Z3 (s): {Z3_TIME}')
    print(f'# calls to Z3: {Z3_NCALLS}')
    print('done')





if __name__ == '__main__':
    parser = ap.ArgumentParser(description = 'Quantitatively repair access control policies')
    parser.add_argument('-p1'  , '--policy1'                 , help = 'policy 1 (AWS)'               , required = True)
    parser.add_argument('-p2'  , '--policy2'                 , help = 'policy 2 (AWS)'               , required = False)  
    parser.add_argument('-rd'  , '--role-definitions'        , help = 'role definitions (Azure)'     , required = False)
    parser.add_argument('-ra1' , '--role-assignment1'        , help = 'role assignment 1 (Azure)'    , required = False)
    parser.add_argument('-ra2' , '--role-assignment2'        , help = 'role assignment 2 (Azure)'    , required = False)
    parser.add_argument('-r'   , '--roles'                   , help = 'roles (GCP)'                  , required = False)
    parser.add_argument('-rb1' , '--role-binding1'           , help = 'role binding 1 (GCP)'         , required = False)
    parser.add_argument('-rb2' , '--role-binding2'           , help = 'role binding 2 (GCP)'         , required = False)
    parser.add_argument('-o'   , '--output'                  , help = 'output file'                  , required = False, default='output')
    # parser.add_argument('-s'   , '--smt-lib'                 , help = 'use SMT-LIB syntax'           , required = False, action = 'store_true')
    parser.add_argument('-e'   , '--enc'                     , help = 'use action encoding'          , required = False, action = 'store_true')
    parser.add_argument('-c'   , '--constraints'             , help = 'use resource type constraints', required = False, action = 'store_true')  
    parser.add_argument('-perm', '--permissiveness-frac'     , help = 'permissiveness fraction'      , required = True)
    parser.add_argument('-test', '--testcases'               , help = 'request testcases'            , required = True)
    parser.add_argument('-b'   , '--bound'                   , help = 'bound'                        , required = True, default = 100)
    args = parser.parse_args()

    # set smt-lib to false
    args.smt_lib = False

    # entry
    start = time.time()
    repair(args)
    end = time.time()
    MAIN_REPAIR_CALL_TIME = (end - start)


    # print('----- META TIMING INFO ------')
    # print(f'main repair time        : {MAIN_REPAIR_CALL_TIME}')
    # print(f'call translator time    : {CALL_TRANSLATOR_TIME}')
    # print(f'get candidates time     : {GET_CANDIDATES_TOTAL_TIME}')
    # print(f'get new policy time     : {GET_NEW_POLICY_TIME}')
    # print(f'get new policy enum time: {GET_NEW_POLICY_ENUMERATED_TIME}')
    # print(f'solver time             : {SOLVER_TIME}')
    # print(f'counter time            : {COUNTER_TIME}')
