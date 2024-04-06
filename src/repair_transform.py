from copy import deepcopy
import json
import sys

# transform a statement's principal, action, resource
def transform_stmt_par(stmt):
    # we ignore deny statements; nothing to do here
    if stmt['Effect'] == 'Deny':
        return [stmt]
    
    transformed_stmts = []
    
    # create an allow statement
    allow_stmt = {'Effect': 'Allow'}
    
    for k in stmt.keys():
        # ignore these keys
        if k in ['Effect']:
            continue

        if 'Not' in k:
            allow_stmt[k[3:]] = '*'
        else:
            allow_stmt[k] = stmt[k]
    
    transformed_stmts.append(allow_stmt)
    
    # create deny statements
    # keys prefixed with "not"
    not_ks = [k for k in stmt.keys() if 'Not' in k]
    
    for not_k in not_ks:
        # create a deny statement
        deny_stmt = {'Effect': 'Deny'}
        
        for k in stmt.keys():
            # ignore these keys
            if k in ['Effect']:
                continue

            if k == not_k:
                deny_stmt[k[3:]] = stmt[not_k]
            elif 'Not' in k:
                deny_stmt[k[3:]] = '*'
            else:
                deny_stmt[k] = stmt[k]
        
        transformed_stmts.append(deny_stmt)
    
    return transformed_stmts

# transform a statement's condition
def transform_stmt_cond(stmt):
    # can't transform a condition if there is none
    if 'Condition' not in stmt.keys():
        return [stmt]

    # we ignore deny statements; nothing to do here
    if stmt['Effect'] == 'Deny':
        return [stmt]
    
    transformed_stmts = []

    # create an allow statement
    cond = {}
    
    for op in stmt['Condition'].keys():
        # negative operators
        if 'Not' in op:
            if 'StringLike' not in cond:
                    cond['StringLike'] = {}

            for k in stmt['Condition'][op].keys():
                # we use StringLike because we introduce a wildcard 
                # even if the original operator was StringNotEquals
                cond['StringLike'][k] = '*'

            if cond['StringLike'] == {}:
                cond.pop('StringLike')

        # positive operators
        else:
            if op not in cond:
                cond[op] = {}

            for k, v in stmt['Condition'][op].items():
                if k not in cond[op]:
                    cond[op][k] = v

            if cond[op] == {}:
                cond.pop(op)

    # isolate principal, action, resource
    allow_stmt = deepcopy(stmt)
    allow_stmt['Condition'] = cond
    
    transformed_stmts.append(allow_stmt)
    
    # create deny statements
    # condition operators prefixed with "not"
    not_ops = [op for op in stmt['Condition'].keys() if 'Not' in op]
    
    for not_op in not_ops:
        # create a deny statement
        cond = {}

        for op in stmt['Condition'].keys():
            if op == not_op:
                cond[op.replace('Not', '')] = stmt['Condition'][op]

            elif 'Not' in op:
                if 'StringLike' not in cond:
                    cond['StringLike'] = {}
                
                for k in stmt['Condition'][op].keys():
                    cond['StringLike'][k] = '*'

                if cond['StringLike'] == {}:
                    cond.pop('StringLike')
            
            else:   
                cond[op] = stmt['Condition'][op]

        # isolate principal, action, resource
        deny_stmt = deepcopy(stmt)
        deny_stmt['Effect'] = 'Deny'
        deny_stmt['Condition'] = cond
        transformed_stmts.append(deny_stmt)
    
    return transformed_stmts

# entry point: transform a policy
def transform_policy(policy):
    transformed_stmts_par = []

    # first pass: transform principal, action, resource
    for stmt in policy['Statement']:
        transformed_stmts_par += transform_stmt_par(stmt)

    # second pass: transform condition
    transformed_stmts_cond = []

    for stmt in transformed_stmts_par:
        transformed_stmts_cond += transform_stmt_cond(stmt)
        
    return {'Statement': transformed_stmts_cond}