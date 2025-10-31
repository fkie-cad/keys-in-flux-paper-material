# keys-in-flux-paper-material

Experimental Artifacts accompanying our DFDS EU 2026 paper **Keys in Flux: Lifespan of Cryptographic Secrets in Memory** (DFDS EU 2026)

---
## TL;DR
- Root layout: `TLS/`, `SSH/`, `IPsec/`, each with its own README and experiment harness.  
- This repo gives you the lab setups, instrumentation scripts, and representative outputs. 
- Zenodo hosts the full datasets (pcaps, memory dumps, full traces).  
- Together they let you reproduce our measurements of how long cryptographic secrets persist in memory

---

## What this repository is
This repository accompanies our DFDS EU 2026 paper on the forensic recoverability of cryptographic key material from memory.  
It provides the code, experiment scaffolding, and representative evidence behind the results reported in the paper.

**Goal:** enable independent verification, reproducibility, and extension of our study.

Our study asks a simple but operationally important question:

**How long do decryption-relevant secrets remain retrievable in memory — across real implementations of TLS 1.2/1.3, SSHv2, and IPsec (IKEv2 + ESP)?**

Instead of treating each protocol as an abstract spec, we instrument *specific implementations*:
- TLS stacks (e.g., OpenSSL / BoringSSL)
- SSH stacks (e.g., OpenSSH, Dropbear, wolfSSH)
- IPsec stacks (e.g., strongSwan, LibreSwan; IKEv2 in user space + ESP in the Linux XFRM kernel path)

For each target, we:
1. hook key derivation,
2. timestamp when each secret first becomes usable,
3. monitor when (or if) that secret is actually cleared from memory.

We refer to these boundary events as:
- **Start of Life (SoL):** first moment the secret exists in memory and is ready to protect live traffic.
- **End of Life (EoL):** earliest moment the secret can no longer be recovered from the relevant address space.

These timelines let us answer questions like:
- Do traffic keys survive normal session teardown?
- Are session keys wiped on rekey, or do old keys linger?
- Are secrets copied into the kernel (IPsec ESP) and then erased from user space, or do they persist?

---

## Zenodo archive (full dataset and large binaries)
Large artifacts (full packet captures, memory snapshots, debugger traces, container images, plot-ready CSVs) are published via Zenodo:

➡ **Zenodo Artifact Archive:**  
https://zenodo.org/records/17496211?token=eyJhbGciOiJIUzUxMiJ9.eyJpZCI6ImQ1YjdhOTY0LWNlZjQtNDc4YS05ZDQ5LWU5N2MzYWNiNWI0YiIsImRhdGEiOnt9LCJyYW5kb20iOiI0OGYzMzIzMTg1NDhiNzljYzRlOTViY2MyZTE2MzRlYyJ9.5jBBHA2oCArwyLjPA7kESO1lPRhB-thiXgfCzaGB8yac1MxKieHqWK1bCw_0W2s5BNZvg_oxZ9L9iJNdiGkHwA

That archive is the authoritative source of:
- full raw experiment captures,
- generated timelines,
- large result sets that are impractical to keep in git.

This GitHub repo contains the *code and scaffolding* needed to regenerate those artifacts.

---

## Repository structure (current)
At the top level:

```text
keys-in-flux-paper-material/
├─ TLS/        # TLS 1.2/1.3 experiments
├─ SSH/        # SSHv2 experiments
├─ IPsec/      # IKEv2 + ESP (IPsec) experiments
├─ LICENSE
└─ README.md   # (this file)
```

Each protocol directory (`TLS/`, `SSH/`, `IPsec/`) is self-contained and has its own `README.md` with instructions specific to that protocol/stack. The per-protocol READMEs cover:

- how to build and launch the Docker(-compose) test environment,
- which implementations are included (e.g. OpenSSH, Dropbear, wolfSSH in `SSH/`; OpenSSL/BoringSSL in `TLS/`; strongSwan/LibreSwan in `IPsec/`),
- how we attach LLDB/Frida to the relevant processes,
- where the extracted secrets, watchpoint logs, and packet captures are written.

### TLS/
Focuses on TLS 1.2/1.3.  
The environment spins up a controlled client/server pair and drives handshakes, rekeys (if supported), and clean teardowns.  
Instrumentation hooks the traffic secret derivation path and records:
- traffic secrets / application data keys,
- timestamps,
- buffer addresses and sizes.

Artifacts typically include:
- PCAPs of the TLS session,
- extracted key material or upstream traffic secrets,
- watchpoint timelines showing when those buffers are overwritten.

### SSH/
Focuses on SSHv2 (OpenSSH, Dropbear, wolfSSH).  
The setup launches an SSH server under debugger control and a scripted client that performs login, optional rekey, and clean disconnect.  
Our LLDB helpers (and, where relevant, Frida hooks) do the following automatically:
- break on the key derivation function (e.g. `kex_derive_keys`),
- dump per-direction traffic keys (client→server / server→client),
- install watchpoints on those buffers,
- timestamp first destructive write.

The resulting logs capture Start of Life at `SSH_MSG_NEWKEYS` and track whether the session keys persist after `SSH_MSG_DISCONNECT` and TCP teardown.

### IPsec/
Focuses on IKEv2 key exchange and ESP traffic protection.  
The testbed brings up two peers, establishes an IKE_SA and CHILD_SA, generates encrypted ESP traffic, triggers rekey via `CREATE_CHILD_SA`, and performs teardown via IKE `INFORMATIONAL` / `DELETE`.  
We trace:
- creation of IKEv2 keying material in user space,
- installation of ESP keys,
- handoff of ESP keys into the Linux XFRM framework,
- disappearance (or persistence) of those keys from user space after offload.

Because ESP keys migrate into the kernel, the IPsec pipeline observes both user space (IKE daemon) and kernel-facing state.

---

## How the measurements work

### 1. Hooking key derivation
For each protocol directory we attach LLDB (or Frida where appropriate) at the function that finalizes new traffic keys:
- SSH: functions like `kex_derive_keys`
- TLS: traffic secret exporters
- IPsec: CHILD_SA installation / ESP key staging

At that moment we record:
- the secret bytes (or the minimal upstream secret from which all traffic keys can be deterministically derived),
- timestamp,
- address,
- length,
- negotiated algorithm.

This moment is the secret’s **Start of Life**.

### 2. Tracking zeroization / reuse
Immediately after capture we arm a hardware/software watchpoint on the first byte of that buffer.  
The first write to that address is treated as the key’s **End of Life**.  
If the process exits or `exec()` replaces it, we log that as well.

This gives us a simple behavioral classification:
- **Optimal:** buffer cleared explicitly and not reused.
- **Reasonable:** buffer rapidly overwritten by unrelated data.
- **Critical:** buffer remains readable well beyond normal teardown.

### 3. Protocol-state alignment
Each experiment also timestamps protocol milestones:
- TLS: `Finished`, session resumption, post-handshake secret updates.
- SSH: `SSH_MSG_NEWKEYS`, rekey messages, `SSH_MSG_DISCONNECT`.
- IPsec: IKE_SA_INIT / IKE_AUTH, CHILD_SA creation, CREATE_CHILD_SA (rekey), INFORMATIONAL + DELETE (teardown).

We then align memory state to protocol state, which lets us make statements like:
- The Dropbear client’s last active traffic keys remained in user-space memory even after a clean disconnect.
- OpenSSH overwrote direction-specific traffic keys almost immediately after teardown.
- ESP traffic keys in IPsec are only briefly present in user space before being handed off to the kernel; after handoff, user-space remnants vanish quickly.

---

## Reproducing an experiment
To replay any experiment, `cd` into the corresponding protocol directory and follow its local `README.md`.  
The flow is similar across TLS / SSH / IPsec:

```bash
# 1. Enter the protocol directory
cd SSH

# 2. Build and start the controlled test setup
docker-compose up --build   # or the variant documented in SSH/README.md

# 3. The containers launch targets under LLDB/Frida.
#    The helper scripts:
#    - break at key derivation
#    - dump fresh secrets
#    - install watchpoints
#    - timestamp events
#
# 4. Outputs will appear in the directory's data/log paths
#    (documented in that subdirectory's README).
```

Those outputs include:
- packet captures,
- extracted key material or upstream derivation inputs,
- watchpoint logs with precise Start-of-Life / End-of-Life timestamps.

You can then run the analysis scripts (parsing, classification, plotting) exactly as described in the per-directory README or by using the helper scripts that ship with that directory.

---

## Reproducing the paper figures
All figures in the paper (lifespan timelines, classification summaries, per-implementation comparisons) can be regenerated from:
1. raw traces exported by the TLS / SSH / IPsec experiments or downloaded from Zenodo,
2. the analysis scripts associated with each protocol directory,
3. the plotting helpers referenced there.

If you regenerate a figure, double-check:
- When the handshake boundary was considered “live traffic starts”
- Whether a rekey actually occurred in that run
- Whether teardown was graceful or abrupt

Those details affect the measured End of Life.

---

## Responsible use
This project is intended for:
- security researchers,
- incident responders,
- forensic analysts,
- implementers interested in zeroization / key lifetime hygiene.

It is **not** intended to aid unauthorized interception of third-party communications.  
All experiments occur in a closed lab using non-production secrets and short-lived sessions.

Do not run these tools against systems you do not control.

---

## Citing this work
If you use this repository or the Zenodo dataset in academic work, please cite the paper and the artifact archive.

**Paper (DFDS EU 2026):**  
> *Keys in Flux: [full paper title TBA]*  
> [Authors TBA]. DFDS EU 2026.

**Artifact / Dataset:**  
> *keys-in-flux-paper-material: Experimental Artifacts for “Keys in Flux”*  
> Versioned Zenodo archive, 2025.  
> Available at the Zenodo Artifact Archive link above.

A BibTeX entry will be added once the camera-ready metadata (title, authors, DOI) is finalized.

---

## 📜 License
See `LICENSE` in this repository for terms of use.

If you plan to reuse the instrumentation code (LLDB/Frida hooks) in other tools, please check the license first and attribute appropriately.

---

## Contact / feedback
We welcome:
- reproducibility reports,
- portability fixes (e.g., other distros, ARM64 variants, different SSH daemons),
- suggestions for additional protocol targets.

Please open an issue or pull request.  
For sensitive disclosures (e.g. newly discovered long-lived key retention in production software), please reach out privately first.
