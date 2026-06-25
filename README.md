# Delivery System — Distributed Homomorphic DES on 3 × ESP32-S3

A privacy-preserving, **distributed** Discrete-Event-System (DES) supervisor for a
cargo-transfer delivery system: three autonomous UAVs sharing one limited-capacity
transfer buffer, with **one ESP32-S3 per UAV**. The shared buffer supervisor is
evaluated **homomorphically** (EC-ElGamal) on every board — the buffer level lives
only as ciphertext in RAM and is never transmitted or stored in clear; each board
only ever decrypts a single "may my UAV act now?" bit.

This is the distributed extension of the single-board
[homomorphic-esp32-ultrades](https://github.com/lacsed/UltraDES-Python) benchmark:
same EC-ElGamal homomorphic core, new decentralized coordination layer.

---

## The running example

```
        a1          b1              a2          b2
   warehouse ──►  D1  ──►  [ buffer B ]  ──►  D2  ──►  client
                 node 1      cap = 2     a3 │          b3
                                           └──►  D3  ──►  client
                                               node 3
                              node 2 = D2
```

* **D1** carries packages warehouse → buffer **B**.
* **D2, D3** collect packages from **B** and deliver them to the client.
* **B** is a shared intermediate store with **limited capacity** (2 packages).

| UAV | Board `NODE_ID` | Controllable start | Effect on buffer B |
|-----|-----------------|--------------------|--------------------|
| D1  | `1` | `a1` (take-off)  | deposits `b1` → **B + 1** |
| D2  | `2` | `a2` (pick-up)   | `a2` → **B − 1** |
| D3  | `3` | `a3` (pick-up)   | `a3` → **B − 1** |

Events in global index order (as in the generated `.h`):
`a1=0, a2=1, a3=2, b1=3, b2=4, b3=5`.
Controllable: `a1, a2, a3`. Uncontrollable: `b1, b2, b3`
(α = start, β = finish in the diagram).

---

## How the DES is modeled

Using **UltraDES-Python** (see `tools/`):

* **Plants** — three UAVs, each a 2-state machine `idle --start--> busy --finish--> idle`.
* **Specification** — one shared buffer `B` of capacity 2: `b1` fills (+1, blocked
  when full), `a2`/`a3` consume (−1, blocked when empty). Because `b1` is
  *uncontrollable*, the supremal controllable supervisor enforces the buffer-full
  limit by disabling `a1` (D1's take-off) — the same mechanism as the classic
  small-factory example.
* The single shared spec couples `b1`, `a2`, `a3`, so local-modular synthesis
  yields **one** supervisor (20 states). After supervisor reduction it collapses
  to a **3-state** automaton that is exactly the **buffer level {0,1,2}** — the
  shared resource each board replicates. This reduced supervisor is what the
  firmware runs.

The supervisor data is emitted as C arrays in PROGMEM in
[`supervisor_data_delivery_system.h`](supervisor_data_delivery_system.h).

---

## What is private (the homomorphic part)

Standard EC-ElGamal on NIST P-192 (≈96-bit security). The buffer-level state vector
is stored only as ciphertext. Enablement of an event is computed by homomorphically
OR-summing the enabled state cells and decrypting **only the resulting bit**. Scalar
blinding is always on (timing/power side-channel resistance on the private key). See
the original project's README for the full crypto design and benchmarks; the core
here is identical.

---

## How the three boards coordinate

**Link: ESP-NOW** — Espressif's connectionless Wi-Fi-layer protocol. No router, no
broker, ~5 ms latency, native broadcast. The *same* sketch is flashed to all three
boards and they only need the **broadcast** peer (`FF:FF:FF:FF:FF:FF`), so you do
**not** hard-code each other's MAC addresses. All boards must share one Wi-Fi
channel (`ESPNOW_CHANNEL`, default 1). **No wiring between boards** — each just needs
power and its antenna.

**Coordination model: replicated buffer + broadcast + 1-token ring**

* **Replicated state** — every board holds an identical encrypted replica of the
  3-state buffer supervisor.
* **Broadcast sync** — the only events that change the buffer are `b1` (+1),
  `a2` (−1), `a3` (−1). When a board fires one it broadcasts `MSG_EVENT` with a
  monotone sequence number; every board applies the same homomorphic transition,
  keeping replicas in lock-step.
* **Token ring** (`node1 → node2 → node3 → node1`) serializes buffer mutations —
  the physical mutual-exclusion that the *permissive* supervisor (which allows both
  `a2` and `a3` when `B ≥ 1`) deliberately does not impose. A board holding the
  token: drains pending events → asks the homomorphic supervisor whether its own
  controllable event is enabled → if enabled, ready and idle, runs one UAV cycle
  and broadcasts its buffer event → passes the token.

A small **readiness gate** (`READY_PCT`) models real UAV availability so the two
consumers D2/D3 don't starve each other under a fixed token order.

---

## Repository layout

```
delivery_system_crypto/
├─ delivery_system_crypto.ino             ← Arduino sketch (open THIS folder in the IDE)
├─ supervisor_data_delivery_system.h      ← generated DES data (PROGMEM C arrays)
├─ sdkconfig.ext                          ← ESP32 build flags (HW MPI / NIST fast path)
└─ tools/
   ├─ generator_ultrades_mono_lmod_lmodred.ipynb  ← UltraDES notebook (incl. delivery_system)
   ├─ gen_delivery.py                     ← regenerate the .h without Jupyter
   ├─ runtimeconfig.json                  ← .NET runtime config used by gen_delivery.py
   └─ sim_protocol.py                     ← host-side verification of the coordination logic
```

Because the repo root **is** the Arduino sketch, the `.ino` file name matches the
folder name and the `.h` / `sdkconfig.ext` sit right beside it — exactly what the
Arduino IDE expects.

---

## Build & flash (Arduino IDE)

1. Open `delivery_system_crypto.ino` (this folder) in the Arduino IDE.
2. Board: **ESP32S3 Dev Module**; defaults are fine; Serial Monitor @ **115200**.
3. Flash each of the three boards with a **different NODE_ID**. Either edit the line
   near the top of the sketch:
   ```cpp
   #define NODE_ID 1     // 1 = D1, 2 = D2, 3 = D3
   ```
   or pass a build flag `-DNODE_ID=2`.
4. Power all three. Node 1 starts holding the token. Watch the Serial Monitors —
   `[FIRE]`, `[SYNC]`, `[TOKEN]` lines show packages flowing warehouse → B → client
   while the encrypted buffer enables update.

> `sdkconfig.ext` enables hardware MPI + NIST fast reduction — essential, the
> firmware is ~5× slower without it.

### Onboard RGB LED as a status indicator

The board's built-in addressable LED shows this node's state at a glance (handy
since you can only watch one Serial Monitor at a time):

| LED | Meaning |
|-----|---------|
| **Blue / Green / Purple** | node identity — **D1 / D2 / D3** |
| **Dim** | idle, does not hold the token |
| **Bright** | currently holds the token |
| **White flash** | this board just fired an event (deposit / pick-up) |

Driven via the core's `rgbLedWrite()` on `RGB_BUILTIN` (GPIO48 on most ESP32-S3
devkits). If your board's LED is on a different pin, override `RGB_LED_PIN` near
the top of the LED section in the sketch.

`SECURITY_FULL_RERANDOMIZE` defaults to `0` here (responsive demo). Set it to `1`
for the research build that also re-randomizes every cell each transition.

---

## Regenerating the supervisor data

Change the buffer capacity, the simulation sequence, or the model and re-emit the
header.

**Option A — UltraDES notebook** (`tools/generator_ultrades_mono_lmod_lmodred.ipynb`).
It now includes the `delivery_system` problem (`build_delivery_system(cap=2)` in
Cell 4). Set `PROBLEM = 'delivery_system'` in Cell 3 and Run All. On Linux/Colab
Cell 1 installs everything automatically.

**Option B — standalone script** (Windows-friendly, no Jupyter):
```
set DOTNET_ROOT=C:\Program Files\dotnet
python tools\gen_delivery.py
```
It bootstraps the .NET runtime + an IPython shim and writes
`supervisor_data_delivery_system.h` into the repo root. Edit `CAP` at the top to
resize the buffer.

---

## Verifying the coordination logic

`tools/sim_protocol.py` parses the **real generated arrays** and runs the firmware's
exact `do_transition` / `event_enabled` / token-ring logic in plaintext across three
simulated nodes (the homomorphic layer just mirrors plaintext). Over 300 turns it
checks: buffer stays in `[0, 2]`, no underflow/overflow, all three replicas stay
identical, enablement always matches the true buffer level, and all three UAVs
participate.
```
python tools\sim_protocol.py
```

---

## References

**Decentralized / modular supervisory control of DES**
- K. Rudie, W. M. Wonham, *Think globally, act locally: decentralized supervisory
  control*, IEEE Trans. Automatic Control 37(11), 1992.
- M. H. de Queiroz, J. E. R. Cury, *Modular supervisory control of large scale
  discrete event systems*, WODES 2000.
- M. H. de Queiroz, J. E. R. Cury, *Synthesis and implementation of local modular
  supervisory control for a manufacturing cell*, WODES 2002.
- W. M. Wonham, *Supervisory Control of Discrete-Event Systems: A Brief History
  (1980–2015)*. https://www.control.utoronto.ca/~wonham/Wonham_SCDES_history.pdf
- C. G. Cassandras, S. Lafortune, *Introduction to Discrete Event Systems*, Springer.

**Implementing SCT supervisors on embedded controllers**
- *PLC-Based Implementation of Local Modular Supervisory Control for Manufacturing
  Systems*, InTech. https://cdn.intechopen.com/pdfs/36409/InTech-Plc_based_implementation_of_local_modular_supervisory_control_for_manufacturing_systems.pdf
- *Local Modular Supervisory Implementation in Microcontroller*. https://www.academia.edu/49530328/Local_Modular_Supervisory_Implementation_in_Microcontroller
- *An implementation methodology for supervisory control theory*, Int. J. Adv. Manuf.
  Technol. https://link.springer.com/article/10.1007/s00170-006-0843-5

**Networked DES control over imperfect channels** (relevant to the broadcast layer)
- *Overview of Networked Supervisory Control with Imperfect Communication Channels*.
  https://arxiv.org/pdf/2010.11491

**ESP-NOW**
- ESP-NOW via Arduino. https://docs.arduino.cc/tutorials/nano-esp32/esp-now/
- Getting Started with ESP-NOW (ESP32 + Arduino IDE), Random Nerd Tutorials.
  https://randomnerdtutorials.com/esp-now-esp32-arduino-ide/

**Crypto / tooling**
- ElGamal, T. (1985). *A public key cryptosystem and a signature scheme based on
  discrete logarithms.* IEEE Trans. Information Theory 31(4).
- UltraDES-Python: https://github.com/lacsed/UltraDES-Python
- mbedTLS ECP: https://mbed-tls.readthedocs.io/

---

*Homomorphic DES core adapted from the ESP32 UltraDES homomorphic supervisor
project; distributed ESP-NOW coordination layer and the delivery-system model added
here.*
