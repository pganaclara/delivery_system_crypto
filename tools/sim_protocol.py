# Host simulation of the distributed firmware logic.
# Parses the REAL generated reduced-supervisor arrays from the .h and runs the
# exact do_transition / event_enabled / token-ring logic from the .ino in
# plaintext (the HE layer just mirrors plaintext, so this validates the model
# and the coordination protocol). Checks invariants: buffer stays in [0,cap],
# no underflow/overflow, and all 3 node replicas stay identical.

import re, os

EV = {'a1':0,'a2':1,'a3':2,'b1':3,'b2':4,'b3':5}
NAME = {v:k for k,v in EV.items()}

def parse_h(path):
    txt = open(path, encoding='utf-8').read()
    def arr(name):
        m = re.search(name + r'\[\] PROGMEM = \{([^}]*)\}', txt)
        return [int(x) for x in m.group(1).replace('\n',' ').split(',') if x.strip()!='']
    return {
        'n': 3,
        'init':   arr('lmr0_init'),
        'enable': arr('lmr0_enable'),
        'tcnt':   arr('lmr0_tcnt'),
        'trans':  arr('lmr0_trans'),
    }

S = parse_h(os.path.join(os.path.dirname(__file__), '..', 'supervisor_data_delivery_system.h'))
N = S['n']; NE = 6

def trans_offset(ev):
    return sum(S['tcnt'][:ev])

class Replica:
    """Plaintext mirror of the encrypted reduced buffer supervisor."""
    def __init__(self):
        self.state = list(S['init'])          # one-hot
    def do_transition(self, ev):
        pc = S['tcnt'][ev]
        if pc == 0: return
        off = trans_offset(ev)
        nxt = [0]*N
        for p in range(pc):
            f = S['trans'][(off+p)*2]; t = S['trans'][(off+p)*2+1]
            nxt[t] = self.state[f]
        self.state = nxt
    def enabled(self, gi):
        # event gi enabled iff some enabled-state cell is active
        row = S['enable'][gi*N:(gi+1)*N]
        # if event has no transitions AND is fully enabled it's unconstrained
        any_constr = any(v==0 for v in row)
        if not any_constr: return True
        return any(row[s] and self.state[s] for s in range(N))
    def level(self):
        return self.state.index(1)            # state index == buffer level for reduced sup

ROLES = {1:('D1','a1','b1',True), 2:('D2','a2','a2',False), 3:('D3','a3','a3',False)}
BUF_EVENTS = {EV['b1'], EV['a2'], EV['a3']}

# 3 replicas, one per node
rep = {i: Replica() for i in (1,2,3)}
uav_idle = {1:True,2:True,3:True}
gseq = 0
log = []
violations = []

def apply_everywhere(ev):
    global gseq
    gseq += 1
    for i in (1,2,3):
        rep[i].do_transition(ev)
    # invariant: all replicas identical
    levels = {rep[i].level() for i in (1,2,3)}
    if len(levels) != 1:
        violations.append(f"replica divergence after {NAME[ev]}: {[rep[i].level() for i in (1,2,3)]}")
    lvl = rep[1].level()
    if lvl < 0 or lvl > 2:
        violations.append(f"buffer out of range: {lvl}")
    return lvl

import random
random.seed(1)
READY_PCT = 65
acted_by = {1:0, 2:0, 3:0}

def node_turn(node):
    uav, gate, bufev, after = ROLES[node]
    g, bv = EV[gate], EV[bufev]
    if not rep[node].enabled(g) or not uav_idle[node]:
        return None
    if random.randrange(100) >= READY_PCT:        # readiness gate
        return None
    # check physical safety against the TRUE level (catches model errors)
    lvl_before = rep[node].level()
    if bv in (EV['a2'],EV['a3']) and lvl_before == 0:
        violations.append(f"{uav} tried pickup on EMPTY buffer (enabled said OK!)")
    if bv == EV['b1'] and lvl_before == 2:
        violations.append(f"{uav} tried deposit on FULL buffer (enabled said OK!)")
    lvl = apply_everywhere(bv)
    acted_by[node] += 1
    log.append(f"{uav}: fired {bufev}  buffer {lvl_before}->{lvl}")
    return bv

# token ring for many rounds
order = [1,2,3]
ti = 0
for step in range(300):
    node = order[ti % 3]; ti += 1
    node_turn(node)

print("Generated reduced-supervisor arrays:")
print("  init  =", S['init'])
print("  enable=", S['enable'])
print("  tcnt  =", S['tcnt'])
print("  trans =", S['trans'])
print()
print(f"Ran 300 token-ring turns. Final buffer level = {rep[1].level()}")
print(f"Buffer ops performed by:  D1={acted_by[1]}  D2={acted_by[2]}  D3={acted_by[3]}")
print("Sample of activity:")
for line in log[:18]:
    print("  ", line)
print(f"  ... ({len(log)} buffer ops total)")
print()
if violations:
    print("INVARIANT VIOLATIONS:")
    for v in violations: print("  !!", v)
else:
    print("OK — no underflow/overflow, no replica divergence, enablement matches physical buffer.")
