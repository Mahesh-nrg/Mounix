# Mobile PT Automation Portal

Upload an APK/XAPK/APKM/APKS, and this portal automatically installs it into a rooted Android
emulator, trusts Burp Suite's CA on the device, points the device's proxy at Burp, attempts a Frida
SSL-pinning bypass, and falls back to an apktool static patch if Frida fails - so you land in Burp
with working interception instead of doing all of that by hand per app.

See `ARCHITECTURE.md` for the full design - read it before changing anything non-trivial here.

## Prerequisites

- The top-level `install_mobile_pt.sh` already run (installs the Android SDK, the rooted
  `MobSF_Pentest` AVD, MobSF via Docker, and writes the repo-root `.env`), **or** the equivalent
  manual steps in the top-level README
- Burp Suite (Community is fine) installed and launched once by hand
- `uv`, `node`/`npm`, `apktool`, `keytool`, `openssl` on `$PATH` (the installer sets these up)

## First-time setup

```bash
./setup.sh
```

This will:
- Create the `mobile_pt` Postgres role/database if it doesn't exist yet
- `uv sync` the backend's dependencies
- Download the `frida-server` build matching the backend's installed `frida` version
- Fetch the httptoolkit Frida unpinning scripts into `scripts/frida/` (gitignored, AGPL-3.0 upstream)
- Generate a debug keystore for the apktool static-patch fallback's re-signing step
- `npm install && npm run build` the frontend

This does **not** write `.env` - that's the top-level `install_mobile_pt.sh`'s job (it writes one
shared `.env` at the repo root, read by both `mobile_pt.sh` and this backend).

## Running

```bash
./run.sh
```

Starts the backend on `http://127.0.0.1:8811`, which also serves the built frontend. Open that URL
and log in with the password you set during install.

Before uploading an app, make sure the emulator and Burp are both up:
- `../mobile_pt.sh status` (or the portal dashboard's "Ensure device running" button)
- Burp Suite running with its proxy listener on (default `127.0.0.1:8080` - this is Burp's own
  default, nothing to configure)

## One-time manual steps (can't be scripted away - see ARCHITECTURE.md)

1. **Burp's "JRE warning" dialog** blocks its very first launch on a given JRE version. Launch Burp
   once by hand, tick "Don't show again for this JRE", click OK. Persists from then on.
2. **Burp Pro only:** the REST API key can't be read back once created (only a hash is stored) -
   `setup.sh` prompts for it; generate one at Settings > Suite > REST API if you don't have it.
   Leave it blank on Community - the health check just no-ops.

## Day-to-day use

1. Upload an APK/XAPK/APKM/APKS through the dashboard.
2. Watch the job detail page's live log as it walks through
   `PARSING -> DEVICE_CHECK -> INSTALLING -> CA_TRUST -> PROXY_SET -> FRIDA_ATTACH -> DONE`
   (or `STATIC_PATCH -> DONE` if Frida's bypass failed and the app is a single, non-split APK).
3. Once `DONE`, the app is running on the device with its traffic routed through Burp - inspect,
   replay, and scan from Burp's own UI as usual. A parallel MobSF static-analysis report link
   appears on the job page once ready.

## Known limitations

See ARCHITECTURE.md's "Known, documented limitations" section - in short: no split-APK static-patch
fallback, apktool patching can't defeat code-level pinning in obfuscated apps, one AVD means jobs
run one at a time, Burp Community shares one session across jobs (Pro gets per-job isolation), and
bypass "success" is judged by the Frida session surviving a grace window rather than a direct
confirmation that traffic reached Burp (Burp's REST API, Pro-only, doesn't expose proxy history
either way).

## Test data

Put a sample APK/XAPK under `../test_apk/` to exercise the pipeline end to end (not included in
this repo).
