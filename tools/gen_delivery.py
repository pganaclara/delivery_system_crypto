# Standalone generator for the delivery_system problem.
# Reuses the EXACT extraction + emission logic from
# generator_ultrades_mono_lmod_lmodred.ipynb (Cells 5 & 7) so the produced
# header is byte-identical to what the notebook would write.
#
# Windows bootstrap: the only ultrades .NET runtime present is 8.0-rc.2, and
# newer IPython moved `display` out of IPython.core.display. We handle both
# here so the same code that runs in Colab also runs locally.

import os, sys

# ── .NET runtime bootstrap (coreclr via explicit runtimeconfig) ───────────────
from clr_loader import get_coreclr
from pythonnet import set_runtime
set_runtime(get_coreclr(runtime_config=os.path.join(os.path.dirname(__file__), 'runtimeconfig.json')))
import clr  # noqa

# ── IPython shim (ultrades.automata imports `display` from the old location) ──
import IPython.core.display as _icd
from IPython.display import display as _disp
if not hasattr(_icd, 'display'):
    _icd.display = _disp

from ultrades.automata import (
    state, event, dfa,
    monolithic_supervisor,
    local_modular_supervisors,
    local_modular_reduced_supervisors,
    parallel_composition,
)

PROBLEM = 'delivery_system'
CAP = 2  # shared buffer B capacity (number of packages)


# ═══════════════════════════════════════════════════════════════════════════════
# CARGO TRANSFER DELIVERY SYSTEM  (running example)
# ═══════════════════════════════════════════════════════════════════════════════
#
#   D1 transports packages warehouse -> buffer B
#   D2, D3 collect from B -> client
#   B is a shared intermediate store with limited capacity (CAP)
#
#   Event mapping (diagram -> code):
#     a1 = alpha1 : D1 starts at warehouse   (controllable)
#     b1 = beta1  : D1 deposits into B       (uncontrollable)  -> B + 1
#     a2 = alpha2 : D2 picks up from B        (controllable)    -> B - 1
#     b2 = beta2  : D2 delivers to client     (uncontrollable)
#     a3 = alpha3 : D3 picks up from B        (controllable)    -> B - 1
#     b3 = beta3  : D3 delivers to client     (uncontrollable)
#
#   Single shared spec B couples b1, a2, a3 -> one local-modular supervisor.
def build_delivery_system(cap=CAP):
    # ── UAV plants : idle --start--> busy --finish--> idle ────────────────────
    d1i = state('D1_idle', True);  d1b = state('D1_busy', False)
    d2i = state('D2_idle', True);  d2b = state('D2_busy', False)
    d3i = state('D3_idle', True);  d3b = state('D3_busy', False)

    a1 = event('a1', controllable=True);  b1 = event('b1', controllable=False)
    a2 = event('a2', controllable=True);  b2 = event('b2', controllable=False)
    a3 = event('a3', controllable=True);  b3 = event('b3', controllable=False)

    D1 = dfa([(d1i, a1, d1b), (d1b, b1, d1i)], d1i, 'D1')
    D2 = dfa([(d2i, a2, d2b), (d2b, b2, d2i)], d2i, 'D2')
    D3 = dfa([(d3i, a3, d3b), (d3b, b3, d3i)], d3i, 'D3')

    # ── Shared buffer spec B (capacity `cap`) ─────────────────────────────────
    # b1 fills (+1, only when not full); a2/a3 consume (-1, only when not empty).
    # b1 is uncontrollable -> supC enforces the full-constraint by disabling a1.
    b1_s = event('b1', controllable=False)
    a2_s = event('a2', controllable=True)
    a3_s = event('a3', controllable=True)

    bstates = [state(f'B{k}', marked=(k == 0)) for k in range(cap + 1)]
    btrans = []
    for k in range(cap):
        btrans.append((bstates[k], b1_s, bstates[k + 1]))        # fill
    for k in range(1, cap + 1):
        btrans.append((bstates[k], a2_s, bstates[k - 1]))        # D2 consume
        btrans.append((bstates[k], a3_s, bstates[k - 1]))        # D3 consume
    B = dfa(btrans, bstates[0], 'B')

    plants      = [D1, D2, D3]
    specs       = [B]
    spec_groups = [[B]]                       # 1 shared spec -> 1 supervisor
    sim_seq     = ['a1', 'b1', 'a1', 'b1', 'a2', 'b2',
                   'a3', 'b3', 'a1', 'b1', 'a2', 'b2']
    return plants, specs, spec_groups, sim_seq


# ═══════════════════════════════════════════════════════════════════════════════
# EXTRACTION HELPERS  (verbatim from notebook Cell 5)
# ═══════════════════════════════════════════════════════════════════════════════

def _global_events(plants, specs):
    names = set()
    for automaton in plants + specs:
        for tr in automaton.Transitions:
            names.add(str(tr.Trigger))
    return sorted(names)


def _extract_ultrades(sup, global_events, name, method):
    state_names = set()
    raw_trans   = []
    for tr in sup.Transitions:
        origin  = str(tr.Origin)
        trigger = str(tr.Trigger)
        dest    = str(tr.Destination)
        state_names.update([origin, dest])
        raw_trans.append((origin, trigger, dest))

    init_name = str(sup.InitialState)
    sorted_states = sorted(state_names)
    if init_name in sorted_states:
        sorted_states.remove(init_name)
        sorted_states = [init_name] + sorted_states

    state_idx = {name_: i for i, name_ in enumerate(sorted_states)}
    n = len(sorted_states)

    init_vec = [0] * n
    if init_name in state_idx:
        init_vec[state_idx[init_name]] = 1

    own_events = sorted({ev for (_, ev, _) in raw_trans})

    transitions = {}
    for (orig, ev, dest) in raw_trans:
        transitions.setdefault(ev, []).append([state_idx[orig], state_idx[dest]])
    for ev in transitions:
        transitions[ev].sort()

    enablement = {}
    for ev in own_events:
        row = [0] * n
        for (orig, trigger, _) in raw_trans:
            if trigger == ev:
                row[state_idx[orig]] = 1
        enablement[ev] = row

    return {
        'name': name, 'method': method, 'num_states': n,
        'num_transitions': sum(len(v) for v in transitions.values()),
        'initial_state': init_vec, 'own_events': own_events,
        'transitions': transitions, 'enablement': enablement,
        'nonblocking': True, 'reachable': (init_name in state_names),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SYNTHESIS  (mirrors Cell 6)
# ═══════════════════════════════════════════════════════════════════════════════

base_plants, base_specs, spec_groups, sim_seq = build_delivery_system()
gevents = _global_events(base_plants, base_specs)
print(f'Problem       : {PROBLEM}  (buffer capacity {CAP})')
print(f'Plants        : {[g.Name for g in base_plants]}')
print(f'Specs         : {[s.Name for s in base_specs]}')
print(f'Global events : {gevents}')

print('Computing monolithic supervisor...')
mono_sup  = monolithic_supervisor(base_plants, base_specs)
mono_dict = _extract_ultrades(mono_sup, gevents, 'Monolithic', 'monolithic')
print(f'  Monolithic states: {mono_dict["num_states"]}, transitions: {mono_dict["num_transitions"]}')

print('Computing local modular supervisors...')
lmod_list = []
sup_idx = 0
for group in spec_groups:
    for sup in local_modular_supervisors(base_plants, group):
        d = _extract_ultrades(sup, gevents, f'S{sup_idx}', 'local_modular')
        lmod_list.append(d)
        print(f'  S{sup_idx}: {d["num_states"]} states  {d["num_transitions"]} trans  own={d["own_events"]}')
        sup_idx += 1

print('Computing local modular reduced supervisors...')
lmod_red_list = []
sup_idx = 0
for group in spec_groups:
    for sup in local_modular_reduced_supervisors(base_plants, group):
        d = _extract_ultrades(sup, gevents, f'S{sup_idx}_red', 'local_modular_reduced')
        lmod_red_list.append(d)
        print(f'  S{sup_idx}_red: {d["num_states"]} states  {d["num_transitions"]} trans')
        sup_idx += 1


# ═══════════════════════════════════════════════════════════════════════════════
# EMISSION  (verbatim from notebook Cell 7)
# ═══════════════════════════════════════════════════════════════════════════════

OUTPUT_H = f'supervisor_data_{PROBLEM}.h'
# Write the header into the repo root (one level up from tools/), next to the .ino.
OUT_PATH = os.path.join(os.path.dirname(__file__), '..', OUTPUT_H)
MONO_FLASH_LIMIT = 1_200_000

def c_array_i8(name, values, per_row=20):
    rows = [values[i:i+per_row] for i in range(0, len(values), per_row)]
    body = ',\n    '.join(', '.join(str(v) for v in r) for r in rows)
    return f'static const int8_t {name}[] PROGMEM = {{\n    {body}\n}};\n'

def c_array_i16(name, values, per_row=16):
    rows = [values[i:i+per_row] for i in range(0, len(values), per_row)]
    body = ',\n    '.join(', '.join(str(v) for v in r) for r in rows)
    return f'static const int16_t {name}[] PROGMEM = {{\n    {body}\n}};\n'

def c_array_u16(name, values, per_row=20):
    rows = [values[i:i+per_row] for i in range(0, len(values), per_row)]
    body = ',\n    '.join(', '.join(str(v) for v in r) for r in rows)
    return f'static const uint16_t {name}[] PROGMEM = {{\n    {body}\n}};\n'

def supervisor_flash_bytes(d, num_events):
    n  = d['num_states']
    tc = sum(len(pairs) for pairs in d['transitions'].values())
    return n + num_events * n + num_events * 2 + tc * 4

def emit_supervisor(d, prefix, gevents):
    n  = d['num_states']
    ne = len(gevents)
    out = []
    out.append(c_array_i8(f'{prefix}init', d['initial_state']))
    enable_flat = []
    for gev in gevents:
        row = d['enablement'].get(gev, None)
        enable_flat.extend(row if row is not None else [1] * n)
    out.append(c_array_i8(f'{prefix}enable', enable_flat))
    trans_flat   = []
    trans_counts = []
    for gev in gevents:
        pairs = d['transitions'].get(gev, [])
        trans_counts.append(len(pairs))
        for (orig, dest) in pairs:
            trans_flat.extend([orig, dest])
    out.append(c_array_u16(f'{prefix}tcnt', trans_counts))
    if trans_flat:
        out.append(c_array_i16(f'{prefix}trans', trans_flat))
    else:
        out.append(f'static const int16_t {prefix}trans[] PROGMEM = {{0}};'
                   f'  // no transitions\n')
    return '\n'.join(out), supervisor_flash_bytes(d, ne)

mono_flash_estimate = supervisor_flash_bytes(mono_dict, len(gevents))
include_mono = (mono_flash_estimate <= MONO_FLASH_LIMIT)

lines = []
lines += [
    f'// {OUTPUT_H}',
    '// Auto-generated by the UltraDES notebook — DO NOT EDIT BY HAND.',
    '// Re-run Cell 7 to regenerate.',
    '//',
    f'// Problem   : {PROBLEM}',
    f'// Events    : {gevents}',
    f'// Sim seq   : {sim_seq}',
    f'// Monolithic: {"INCLUDED" if include_mono else "OMITTED (exceeds MONO_FLASH_LIMIT)"}',
    '',
    '#pragma once',
    '#include <stdint.h>',
    '// pgmspace.h is provided automatically by the ESP32 Arduino core.',
    '',
]
ne = len(gevents)
lines += [
    '// Total number of events across all plants and specs.',
    f'#define EVENT_COUNT {ne}',
    '',
    '// Number of steps in the simulation sequence.',
    f'#define SIM_SEQ_LEN {len(sim_seq)}',
    '',
]
lines.append('// Event names in global index order (index = position in EVENT_NAMES[]).')
for gi, ev in enumerate(gevents):
    lines.append(f'static const char EV_{gi}[] PROGMEM = "{ev}";')
lines += [
    'static const char* const EVENT_NAMES[] PROGMEM = {',
    '    ' + ', '.join(f'EV_{gi}' for gi in range(ne)),
    '};',
    '',
]
sim_idx = [gevents.index(ev) for ev in sim_seq]
lines.append('// Simulation sequence: each entry is a global event index into EVENT_NAMES[].')
lines.append(c_array_u16('SIM_SEQ', sim_idx))
lines.append('')
lines += [
    '// Descriptor struct — one instance per supervisor.',
    '// All pointer fields point into PROGMEM arrays defined below.',
    'struct SupDesc {',
    '    const char*      name;       // supervisor label (PROGMEM string)',
    '    uint16_t         num_states; // total number of states',
    '    const int8_t*    init;       // one-hot initial state vector [num_states]',
    '    const int8_t*    enable;     // enablement matrix [EVENT_COUNT * num_states]',
    '    const uint16_t*  tcnt;       // transition pair counts per event [EVENT_COUNT]',
    '    const int16_t*   trans;      // flat (from,to) transition pairs',
    '};',
    '',
]
lines.append(f'// ── Local modular supervisors ({len(lmod_list)} total) ──────────────────────────────────')
lines.append(f'#define LMOD_COUNT {len(lmod_list)}')
lines.append('')
total_lmod_flash = 0
for idx, d in enumerate(lmod_list):
    prefix = f'lm{idx}_'
    lines.append(f'// {d["name"]}  —  {d["num_states"]} states, {d["num_transitions"]} transitions')
    code, fb = emit_supervisor(d, prefix, gevents)
    lines.append(code)
    total_lmod_flash += fb
    lines.append(f'static const char LMOD_{idx}_NAME[] PROGMEM = "{d["name"]}";')
    lines.append('')
lines.append('static const SupDesc LMOD_SUPS[] = {')
for idx, d in enumerate(lmod_list):
    prefix = f'lm{idx}_'
    lines.append(f'    // {d["name"]}: {d["num_states"]} states')
    lines.append(f'    {{ LMOD_{idx}_NAME, {d["num_states"]}, '
                 f'{prefix}init, {prefix}enable, {prefix}tcnt, {prefix}trans }},')
lines.append('};')
lines.append('')
lines.append(f'// ── Local modular reduced supervisors ({len(lmod_red_list)} total) ──────────────────────')
lines.append(f'#define LMOD_RED_COUNT {len(lmod_red_list)}')
lines.append('')
total_lmod_red_flash = 0
for idx, d in enumerate(lmod_red_list):
    prefix = f'lmr{idx}_'
    orig   = lmod_list[idx] if idx < len(lmod_list) else None
    ds     = (d['num_states']      - orig['num_states'])      if orig else 0
    dt     = (d['num_transitions'] - orig['num_transitions']) if orig else 0
    lines.append(f'// {d["name"]}  —  {d["num_states"]} states ({ds:+d}), {d["num_transitions"]} transitions ({dt:+d})')
    code, fb = emit_supervisor(d, prefix, gevents)
    lines.append(code)
    total_lmod_red_flash += fb
    lines.append(f'static const char LMOD_RED_{idx}_NAME[] PROGMEM = "{d["name"]}";')
    lines.append('')
lines.append('static const SupDesc LMOD_RED_SUPS[] = {')
for idx, d in enumerate(lmod_red_list):
    prefix = f'lmr{idx}_'
    lines.append(f'    // {d["name"]}: {d["num_states"]} states')
    lines.append(f'    {{ LMOD_RED_{idx}_NAME, {d["num_states"]}, '
                 f'{prefix}init, {prefix}enable, {prefix}tcnt, {prefix}trans }},')
lines.append('};')
lines.append('')
if include_mono:
    lines.append(f'// ── Monolithic supervisor — {mono_dict["num_states"]} states ─────────────────────────')
    code, _ = emit_supervisor(mono_dict, 'mono_', gevents)
    lines.append(code)
    lines += [
        f'static const char MONO_NAME[] PROGMEM = "{mono_dict["name"]}";',
        f'#define MONO_NUM_STATES {mono_dict["num_states"]}',
        'static const SupDesc MONO_SUP = {',
        f'    MONO_NAME, {mono_dict["num_states"]}, '
        f'mono_init, mono_enable, mono_tcnt, mono_trans',
        '};',
        '#define HAS_MONO 1',
    ]
else:
    lines += [
        '// Monolithic supervisor omitted — exceeds MONO_FLASH_LIMIT.',
        '#define HAS_MONO 0',
    ]
lines.append('')

h_content = '\n'.join(lines) + '\n'
with open(OUT_PATH, 'w', encoding='utf-8') as f:
    f.write(h_content)
print(f'\nWritten : {OUTPUT_H}  ({os.path.getsize(OUT_PATH):,} bytes)')
print(f'  Local modular flash         : {total_lmod_flash:,} bytes')
print(f'  Local modular reduced flash : {total_lmod_red_flash:,} bytes')
if include_mono:
    print(f'  Monolithic flash            : {mono_flash_estimate:,} bytes')
