# Mobile PT Automation Portal — Architecture

**Purpose:** upload an APK/XAPK/APKM/APKS through a web portal and have it automatically installed
into a rooted Android emulator, have its traffic routed into Burp Suite (Community or Pro), and have
SSL pinning bypassed (Frida first, apktool static patch as a fallback) — so a human pentester lands
straight in Burp with working interception, instead of doing all of that setup by hand per app.

This document is meant to be handed to a **fresh Claude Code session, on a different machine**, and
be enough to reconstruct this system's design decisions without replaying the original conversation.

## System Map

```
<repo-root>/
├── mobile_pt.sh              # Android SDK/AVD + MobSF Docker lifecycle (setup/launch/status/teardown)
├── logs/                     # mobile_pt.sh's own logs
├── mobsf_data/                # MobSF's persistent volume (chown 9901:9901, automated in start_mobsf())
├── test_apk/                  # drop a sample XAPK/APK here for end-to-end testing
└── portal/                    # <-- this project
    ├── ARCHITECTURE.md         # this file
    ├── setup.sh                # one-time: Postgres role/db, .env, frida-server download, keystore, frontend build
    ├── run.sh                  # starts the backend (which also serves the built frontend)
    ├── backend/                # FastAPI, managed with `uv`
    │   └── app/
    │       ├── main.py            # app assembly, mounts routers + serves frontend/dist
    │       ├── config.py          # loads the repo-root .env into a Settings object
    │       ├── db.py              # Postgres engine + table creation
    │       ├── models.py          # Job, JobLogLine (SQLModel)
    │       ├── auth.py            # single-password login, signed-cookie session
    │       ├── events.py          # in-memory pub/sub for the live WebSocket log stream
    │       ├── worker.py          # single sequential job queue (one AVD -> one job at a time, by design)
    │       ├── routers/           # jobs (upload/list/detail/logs), device (status/start), ws (live log)
    │       └── services/
    │           ├── apk_inspect.py       # apkfile-based parsing + Flutter detection
    │           ├── adb_service.py       # install*, CA push (tmpfs overlay, no reboot - see below), proxy
    │           ├── burp_service.py      # CA fetch, REST health check (Pro only), launch-if-not-running
    │           ├── frida_service.py     # frida-server deploy + spawn/attach the fetched unpinning scripts
    │           ├── apktool_service.py   # static-patch fallback (decompile/patch/rebuild/sign)
    │           ├── mobsf_service.py     # parallel static-scan report via the existing MobSF container
    │           ├── device_lifecycle.py  # thin wrapper that shells out to ../../../mobile_pt.sh
    │           └── pipeline.py          # the job state machine tying all of the above together
    ├── scripts/
    │   ├── burp-config-template.json    # pre-set proxy listener (127.0.0.1:8080) for a fresh Burp project
    │   └── frida/                       # fetched at install time from httptoolkit/frida-interception-and-unpinning
    │                                     # (AGPL-3.0-or-later) — gitignored, not vendored, so this repo stays MIT
    ├── frontend/                        # React + Vite + TS: Login, Dashboard, JobDetail pages
    └── data/                            # gitignore-worthy: uploads/, certs/, keystores/, frida-server binary
```

## Why these specific choices

- **FastAPI + React/Vite, Postgres, single shared password** — a pragmatic default for a
  single-analyst local lab, not a multi-tenant design. Swap in real auth/multi-user support if you
  extend this for a team.
- **`mobile_pt.sh` is reused, not reimplemented.** The portal shells out to it
  (`device_lifecycle.py`) for AVD/MobSF start/stop/status rather than duplicating that logic.
- **One AVD -> jobs run strictly sequentially** (`worker.py`, a single asyncio consumer). This is
  hardware reality, not an arbitrary limitation: there is exactly one emulator.
- **MobSF is not the dynamic-analysis proxy.** It and Burp both want to own the interception proxy
  for a running app - only Burp gets that role. MobSF is used purely for a parallel static report via
  its own REST API.
- **The `frida` Python bindings are used directly, not the `objection`/`frida` CLIs**, so attach
  failure/crash can be detected programmatically (`session.on("detached", ...)`) instead of scraping
  CLI output.
- **CA trust goes into the *system* store (`/system/etc/security/cacerts/`), not a user-added cert.**
  Apps targeting API 24+ trust system CAs by default without any per-app opt-in; only user-added certs
  are blocked by default network security config. This only works because the AVD is rooted
  (`google_apis`, non-Play-Store image - see `mobile_pt.sh`).
- **Getting a writable path to that directory avoids `adb root`, `adb remount`, and `adb reboot`
  entirely** - all three were found, hands-on, to be unsafe on at least one emulator/kernel build:
  `adb root` can reliably wedge the connection by racing the emulator's own post-boot setup, and any
  in-guest reboot risks an infinite AVB "vbmeta digest mismatch" loop that looks identical from the
  outside to a hung boot. Instead, `adb_service.py` uses `su 0` (the image is rootable without
  restarting `adbd`) to bind-mount a tmpfs directly over just `/system/etc/security/cacerts/`, after
  first preserving the existing system CAs into it - no reboot, no remount of the verity/AVB-protected
  root filesystem at all. The emulator launches with **no** `-wipe-data` by default for this reason -
  safe specifically because nothing in this codebase calls `adb root`/`remount`/`reboot` on it (the
  su-0-tmpfs approach above is what makes that possible without ever needing to wipe). `-wipe-data`
  remains available only as a manual, one-off recovery step if the AVD's on-disk state ever does get
  corrupted some other way (see the comment above `start_emulator_if_needed()` in `mobile_pt.sh` for
  the exact recovery command).
- **Frida script set is fetched at install time from httptoolkit/frida-interception-and-unpinning**
  (AGPL-3.0-or-later - install_mobile_pt.sh downloads it into `portal/scripts/frida/`, gitignored, so
  this repo's own MIT license isn't affected; keep its `LICENSE` file alongside if you redistribute
  those scripts separately), concatenated in the order the upstream project documents (`config.js`
  first, then hooks, then Android-specific scripts), with `CERT_PEM`/`PROXY_HOST`/`PROXY_PORT`
  substituted per-run rather than editing the fetched files. Flutter apps get
  `android-disable-flutter-certificate-pinning.js` **appended** to the same base set (it's an addon
  per upstream docs, not a replacement) because Flutter pins inside `libflutter.so`'s own BoringSSL,
  bypassing the Android TrustManager entirely.
- **Static-patch fallback (apktool) only supports single, non-split APKs.** A network security
  config patch lives in the base APK's manifest; reassembling a patched multi-APK install isn't
  implemented. Split-APK/XAPK uploads that fail the Frida path just fail with a clear reason instead.
- **MobSF's own DAST (`mobsfy()`) and the Frida+Burp phase (`sast_dast`/`sast_dast_burp` analysis
  modes) can target EITHER the project's AVD or a physical Android device connected via adb, chosen
  per job by the user.** `POST /api/jobs/{id}/start` takes `device_target_type`
  (`"emulator"|"physical"`) and `device_target_ip`; the New Scan UI runs a live connectivity check
  (`POST /api/device/check`) before letting the user queue the job. `pipeline.py`'s
  `resolve_device_serial()` resolves one serial from that choice, used for both the `MOBSF_DAST`
  phase and the Frida+Burp phase - never a mix of the two devices in one job. Why the choice exists:
  MobSF's device setup requires `/system` mounted writable, which requires disabling AVB verity -
  and on at least one AVD build, doing that by any method reliably prevents the guest from ever
  reaching `boot_completed` again, while real hardware has no such constraint (though it does have
  its own quirks - Magisk's `su` can silently no-op on a bare `su 0 <cmd>`, and frida-server is
  architecture-specific). Picking the emulator for a DAST mode is still allowed; it will predictably
  hit the same `/system`-writable failure - that tradeoff is the user's to make per job. The Burp
  proxy host address (`BURP_PROXY_HOST_EMULATOR` / `BURP_PROXY_HOST_FROM_DEVICE`) and the Frida
  `config.js` PROXY_HOST substitution both branch on the same per-job choice, since the emulator's
  `10.0.2.2` loopback alias is unreachable from real hardware and a physical device needs the host's
  actual LAN IP.
- **Genymotion Desktop is a third, fully operational `device_target_type`, used for the `MOBSF_DAST`
  phase AND the Frida+Burp pipeline** - `resolve_device_serial()` treats it like any other target;
  whichever device a job picks drives the whole job, same as `"emulator"`/`"physical"`. It exists
  because it's the one device with a genuinely writable `/system` without any verity/AVB workaround:
  MobSF's own logs state official DAST support is limited to Android Emulator, Corellium, and
  Genymotion, the project's AVD can't safely provide a writable `/system`, and a Magisk-rooted
  physical device can't either (systemless root never actually remounts `/system`). Genymotion
  Desktop needs VirtualBox as its hypervisor and a free personal Genymotion account.
  - **Networking is the real gotcha, fully solved and automated:** Genymotion's free tier gates
    NAT/Bridge network-mode changes behind a Pro license (`gmtool`/GUI both refuse), and its own
    launcher unconditionally resets `nic1` (the adapter it manages, which adb uses) back to Host-Only
    on every single VM start regardless of external changes - Host-Only has **no outbound route at
    all** (confirmed: not even to its own gateway), so a Genymotion guest can't reach anything, Burp
    included, without a real fix. The fix is additive, not a workaround: a *second*, separate
    NAT-only adapter (`nic3` - confirmed to survive every restart untouched, unlike `nic1`) provides
    a real outbound path, and a short in-guest fixup on every boot (bring the link up, get a DHCP
    lease via Android's native `dhcptool`, register it as a real `netd` network and set it default
    via `ndc`) is what actually lets traffic out - a kernel route alone isn't enough, Android's own
    policy routing (`ip rule`) blocks anything not tied to a registered network. `nic1`/adb
    reachability is never touched by any of this.
  - `mobile_pt.sh` owns this whole lifecycle end to end and self-heals it: `cmd_launch` (default-on,
    `--no-genymotion` to skip) and the dedicated `mobile_pt.sh heal` command both call
    `setup_genymotion()` - boot, ensure the NAT adapter, run the in-guest fixup, and verify *real*
    connectivity to Burp before declaring success. Every step that showed real transient flakiness
    live (a `gmtool` license/session hiccup, the guest's network stack needing a moment to settle) is
    retried automatically via a generic `with_retries()` helper, including a power-cycle
    auto-recovery if the VM reports running but never actually becomes reachable - failures reported
    to the user mean every autonomous retry already ran out, not "first attempt didn't work."
  - Genymotion needs its own distinct Burp proxy host **and port** (`burp_proxy_host_genymotion`,
    `burp_proxy_port_genymotion` - the host's real LAN IP on a separate port from the
    emulator/physical paths' shared 8080, e.g. 8090). This listener is **not** provisioned by
    `burp-config-template.json` (specific-address listeners didn't reliably bind there in testing) -
    add it by hand in Burp's own GUI (Proxy settings > add a listener bound to the host's LAN IP on
    that port) once, after install. `adb_service.set_global_proxy()` and
    `frida_service._patch_config()` both select host *and* port per `device_target_type`, not just
    host.

## Known, documented limitations (not bugs — deliberately out of scope for v1)

- **No API-driven confirmation that traffic actually reached Burp.** Burp Pro's REST API only
  covers scan orchestration and `/burp/versions` health — it does **not** expose proxy/HTTP history,
  and Community has no REST API at all. So "Frida bypass succeeded" is judged by an indirect but
  meaningful signal instead: the script injected without error, the app was resumed, and the Frida
  session survived a grace window without detaching/crashing (root/tamper detection and
  native-pinning crashes are exactly what would make it detach). A future improvement would be a
  small custom Burp extension (Montoya API, or the PortSwigger MCP server) that surfaces matched
  traffic to the backend — not built here.
- **apktool static-patch is best-effort.** It can't remove pinning logic baked into an app's own
  code (e.g. a hardcoded OkHttp `CertificatePinner`), only manifest/network-security-config-level
  restrictions. Obfuscated apps have a real, expected failure rate.
- **Split-APK/XAPK uploads have no static-patch fallback** (see above).
- **Concurrency is intentionally 1.** One AVD, one job at a time.
- **The emulator's data is wiped on every cold launch** (`mobile_pt.sh` always passes `-wipe-data`).
  Installed apps and any prior `/system` writes don't persist across a restart of the emulator
  process itself. This is fine for how the portal uses it (every job reinstalls its own app and CA
  trust is re-applied idempotently each boot) but means the AVD is not a place to keep anything you
  want to survive a `mobile_pt.sh teardown && launch`.
- **Burp Community loses per-job session isolation.** On Pro, each job gets a fresh Burp project
  file; Community can't reload a project from the CLI, so every job shares whatever Burp Community
  instance is already running - clear its proxy history between targets if that matters to you.

## One-time manual steps a fresh setup still needs (can't be scripted away)

1. **Burp Suite's "JRE warning" dialog** blocks its first-ever launch on a given JRE version (a
   modal Swing dialog, not suppressible via `--config-file`). Launch Burp once by hand, tick "Don't
   show again for this JRE", click OK — this persists in Burp's own config from then on.
2. **Burp's REST API key's plaintext isn't recoverable once set** (Pro only; Community has no REST
   API) — `UserConfig.json` only stores a hash. `setup.sh` prompts for it (Burp > Settings > Suite >
   API); if you don't have the original, generate a fresh key there and paste it in. Leave it blank
   on Community.
3. **`chown -R 9901:9901` on `mobsf_data/`** is automated inside `mobile_pt.sh`'s `start_mobsf()`,
   so this is no longer manual — noted here so a future reader understands why that line exists if
   they're wondering.

## Verification

- `mobile_pt.sh status` shows the emulator + MobSF container state.
- `curl -s http://127.0.0.1:8811/api/device/status` (authenticated) shows emulator/MobSF/Burp
  reachability from the portal's point of view.
- Upload a sample APK/XAPK through the UI (or `curl -F file=@...` to `/api/jobs`) and watch
  `/api/jobs/<id>/logs` or the WebSocket-driven job detail page for the pipeline walking through
  `PARSING -> DEVICE_CHECK -> INSTALLING -> CA_TRUST -> PROXY_SET -> FRIDA_ATTACH -> DONE`.
