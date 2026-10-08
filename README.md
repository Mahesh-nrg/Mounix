# Mobile PT Automation

Upload an APK, XAPK, APKM, or APKS to a web portal. The portal installs it on a rooted Android
device or emulator, trusts Burp Suite's CA certificate on the device, points the device proxy at
Burp, tries a Frida SSL-pinning bypass, and falls back to an apktool static patch if Frida fails.
You end up in Burp with working interception instead of doing each step by hand.

A parallel MobSF static-analysis report is generated for each app.

<!-- TODO: the three GIFs below do not exist yet. Record them against a running install (see
     portal/README.md) and add them under docs/img/, or remove these lines. The links are broken
     until then. -->

![Uploading an app in the portal](docs/img/portal-upload.gif)

![Live job log while an app is being set up](docs/img/job-live-log.gif)

![Dashboard with job states](docs/img/dashboard.gif)

## Architecture

```text
 +---------------------+       proxy (host:port)       +------------------+      MCP (SSE)      +-----------------+
 | Android device or   | ----------------------------> |  Burp Suite      | <-------------------> |  AI client      |
 | emulator            |   CA trusted in system store  |  (Community +    |                      |  (e.g. Claude   |
 | (app under test)    |                               |   MCP Server ext)|                      |   Code)         |
 +----------^----------+                               +------------------+                      +-----------------+
            |
            | adb (install, CA push, proxy settings, frida-server)
            |
 +----------+----------+       REST / upload        +------------------+
 | Mobile PT portal    | --------------------------> |  MobSF (Docker)  |
 | backend + web UI    |  static report (parallel)   |  static analysis |
 +---------------------+                             +------------------+
```

Pipeline per job:

1. The portal parses the APK and detects the framework (including Flutter).
2. It checks the device, installs the app, and pushes Burp's CA certificate to the system store.
3. It sets the device proxy to Burp.
4. It attaches Frida with the unpinning scripts. If that fails and the upload is a single APK, it
   falls back to an apktool static patch and re-signs the app.
5. The job reaches `DONE`. The app now runs with its traffic routed through Burp.

## Prerequisites

- Debian, Ubuntu, or Kali Linux, with `sudo` access.
- Hardware virtualization: KVM enabled (`/dev/kvm` must exist). Check with `ls -l /dev/kvm`.
- 16 GB RAM suggested. The emulator, Burp, PostgreSQL, and MobSF all run on the same host.
- A free Genymotion personal account, for the Genymotion device target.
- Burp Suite Community Edition (free). Burp Professional also works (`BURP_EDITION=pro` in `.env`),
  but this guide and the default setup use Community.
- A GitHub account, to clone and contribute. Cloning a public repository over HTTPS needs no login.
- Docker, for MobSF. Your user must be able to run `docker` without `sudo` (see Troubleshooting).

<!-- TODO: confirm the minimum disk space the installer needs (Android system image, MobSF image). -->

## Quick install

```bash
git clone https://github.com/Mahesh-nrg/Mounix.git
cd Mounix
sudo ./install_mobile_pt.sh
```

This installs apt packages, Docker + the MobSF image, and `uv`; guides you through installing
Genymotion and Burp by hand (see the next section); asks which network interface to bind Burp's
proxy and MCP server to; optionally logs in to GitHub CLI; and writes a repo-root `.env` plus a
`burp-mcp-client.json`. It asks for:

- The portal login username (default `admin`) and password. Only a bcrypt hash is stored.
- The Burp proxy listener port (default `8080`) and the Burp MCP server port (default `9876`).
- Which network interface to bind them to (see [Network interface choice](#network-interface-choice)).
- Whether to also log in to `gh` now (`gh auth login --web`); you can skip and do this later.

Then finish the portal-specific setup (Postgres role/db, Python/Node deps, frida-server, the
fetched Frida scripts, and the frontend build):

```bash
cd portal
./setup.sh
```

`setup.sh` also asks for a database password if the `mobile_pt` Postgres role already existed
before this install, and - only if you set `BURP_EDITION=pro` in `.env` - for a Burp REST API key.

## Manual setup: Burp Suite Community with the MCP server

`install_mobile_pt.sh` does not install Burp itself (Burp's own license terms mean it can't be
bundled or silently downloaded). Do this once by hand, when the installer pauses and asks for it.

1. **Install Burp Suite Community.** Download it from
   <https://portswigger.net/burp/communitydownload> and run the installer. Burp bundles its own
   Java runtime. (Kali/Debian also has `apt install burpsuite`, which installs Community.)
2. **Launch Burp once.** On the first launch Burp shows a JRE warning dialog. Tick
   "Don't show again for this JRE", then click OK. This setting persists.
   <!-- TODO: confirm the exact dialog wording in the current Burp version. -->
3. **Install the MCP Server extension.** Go to **Extensions > BApp Store**, search for
   **MCP Server**, and click **Install**. The extension is published by PortSwigger and its BApp
   listing is marked compatible with both Community and Professional.
4. **Enable the MCP server.** A new **MCP** tab appears. Open it and turn the server on. Note the
   host and port it reports. The default is `127.0.0.1:9876` - enter this when the installer asks.
5. **Confirm the proxy listener.** Go to **Proxy > Proxy settings > Proxy listeners**. The default
   listener is `127.0.0.1:8080` and must be **Running**. If your device is not the emulator (a
   physical phone, or Genymotion), add a second listener bound to this host's LAN IP - see
   [Network interface choice](#network-interface-choice) - on a different port (the default
   Genymotion setup in `.env` expects `8090`). Burp Community can't have this LAN listener
   provisioned by `burp-config-template.json` or persisted across restarts, so add it here by hand
   each time you restart Burp.
6. **Point your AI client at the MCP server.** `install_mobile_pt.sh` already wrote
   `burp-mcp-client.json` in the repo root with the host/port you chose - merge its `mcpServers`
   entry into your own client config (for Claude Code, `.mcp.json` in the project root or your home
   directory):

   ```json
   {
     "mcpServers": {
       "burp": {
         "type": "sse",
         "url": "http://127.0.0.1:9876"
       }
     }
   }
   ```

   <!-- TODO: verify the endpoint path against the current extension release. Some versions
        expect http://HOST:PORT/sse. The extension also ships a stdio proxy JAR for clients that
        only support stdio. -->

Burp's CA certificate does not need to be installed by hand. The portal fetches it and pushes it to
the device's system store during the `CA_TRUST` step.

## GitHub login with `gh`

Cloning the public repository needs no login. You need the GitHub CLI to push branches, open pull
requests, or use `gh` commands. `install_mobile_pt.sh` offers to do this step for you
(`gh auth login --web`); to do it yourself instead:

```bash
# Install gh (Debian/Ubuntu/Kali): sudo apt install gh
gh auth login --web
```

Choose **GitHub.com**, then **HTTPS**, then follow the browser prompt with the one-time code the
terminal shows. Check the result with `gh auth status`.

## Network interface choice

Burp's proxy listener, the MCP server, and the portal dashboard each bind to one network interface.
The choice decides which machines can reach them. `install_mobile_pt.sh` asks once and writes the
same address to both `BURP_BIND_HOST` and `PORTAL_HOST` in `.env`.

| Bind address | Who can connect | When to use it |
|--------------|-----------------|----------------|
| `127.0.0.1` (default) | This machine only | Emulator on the same host. The emulator reaches the host through `10.0.2.2`. |
| A LAN IP, for example `192.168.1.100` | Devices on the same LAN | Physical device, or a Genymotion guest on the host's LAN. |
| `0.0.0.0` | Every interface, and any network the host is on | Avoid. See the warning below. |

> **Security warning: do not bind to 0.0.0.0 on an untrusted network.**
> The Burp MCP server gives any client that can reach it control of Burp, including sending
> requests, editing scope, and starting scans. A proxy listener on `0.0.0.0` lets any host on the
> network route traffic through your Burp instance, and that traffic can include credentials and
> session tokens. Use `127.0.0.1` where possible. Use a single LAN IP when a device must reach
> Burp. Firewall the MCP port (default `9876`) so only your AI client's machine can reach it.
> `install_mobile_pt.sh` asks you to confirm explicitly before accepting `0.0.0.0`.

## Usage

1. Start the portal:

   ```bash
   cd portal
   ./run.sh
   ```

   The backend listens on port `8811` (set in `portal/run.sh`), on the address in `.env`'s
   `PORTAL_HOST` (`127.0.0.1` by default), and serves the web UI at that address.

2. Open the portal in a browser and log in with the password you set during installation.
3. Before uploading, make sure the device and Burp are both up:
   - The dashboard's **Ensure device running** button starts the emulator and MobSF. The equivalent
     command is `./mobile_pt.sh status` from the repo root.
   - Burp is running, its proxy listener is **Running**, and the MCP server is enabled.
4. Upload an APK, XAPK, APKM, or APKS from the dashboard.
5. Open the job page and watch the live log. A job moves through these states:

   ```text
   PARSING -> DEVICE_CHECK -> INSTALLING -> CA_TRUST -> PROXY_SET -> FRIDA_ATTACH -> DONE
   ```

   If Frida fails and the upload is a single, non-split APK, the job goes to `STATIC_PATCH -> DONE`.
   Split uploads (XAPK, APKM, APKS) have no static-patch fallback. They fail with a clear reason.

   A `sast_dast_burp` job pauses once at `AWAITING_BURP_CONFIRM` before touching Burp, since on
   Burp Pro this restarts Burp with a fresh per-job project (closing whatever is currently open);
   on Community, Burp is never restarted, but the dashboard still asks you to confirm since the
   device's traffic is about to start flowing into whatever Burp session is already running.

6. When the job reaches `DONE`, open the app on the device. Its traffic appears in Burp. Use the
   AI client to inspect or replay it through the MCP tools. The MobSF static report link appears on
   the job page when it is ready.

Jobs run one at a time, because there is one emulator. Queued jobs wait.

<!-- TODO: confirm the analysis mode names shown in the UI (for example sast_dast and
     sast_dast_burp). The pipeline has a MobSF dynamic-analysis phase and the pause state above
     that these modes use. Document them once the UI labels are final. -->

Frida's success check is indirect. It treats the bypass as successful if the script loads, the app
resumes, and the Frida session stays attached for a short grace window. Burp's REST API (Pro only -
Community has none) does not expose proxy history either way, so the portal cannot confirm from an
API that traffic reached Burp. Check the Burp HTTP history yourself.

## Known limitations

- **Burp Community shares one session across jobs.** Burp Pro gets a fresh, isolated project file
  per job; Community can't reload a project from the CLI, so clear its proxy history between
  targets yourself if that matters to you. See `portal/ARCHITECTURE.md`.
- **No split-APK static-patch fallback**, and apktool patching can't defeat pinning logic baked
  into an app's own code (only manifest/network-security-config-level restrictions).
- **One AVD means jobs run one at a time.**

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Emulator fails to start, or `/dev/kvm` is missing | KVM is not enabled | Enable VT-x (Intel) or AMD-V in the firmware. Install `qemu-kvm`. Add your user to the `kvm` group, log out, and log back in. Check with `ls -l /dev/kvm`. |
| `permission denied ... /var/run/docker.sock` | Your user is not in the `docker` group | Run `sudo usermod -aG docker "$USER"`, then log out and back in. `install_mobile_pt.sh` does this for `$SUDO_USER` automatically. |
| Burp shows the JRE warning and does not start | First launch on this Java runtime | Launch Burp once by hand. Tick "Don't show again for this JRE", then click OK. |
| Burp MCP client cannot connect | MCP server disabled, wrong host or port, or bound to `127.0.0.1` while the client is on another machine | Open the MCP tab, confirm it is enabled, and match the host and port in your client's MCP config / `burp-mcp-client.json`. |
| Device cannot reach the proxy | Listener bound to `127.0.0.1` while the device is remote, or wrong `BURP_PROXY_HOST_FROM_DEVICE`/`BURP_PROXY_HOST_GENYMOTION` | Bind (or add) a listener on the LAN IP and set the matching `.env` variable to the same address. Use `10.0.2.2` only for the emulator. |
| Genymotion target not found | Genymotion Desktop is not installed, the VM name differs, or `gmtool` is not on the path | Install Genymotion Desktop, create the VM, and set `GENYMOTION_VM_NAME` in `.env` to its exact name. <!-- TODO: expose the gmtool path as a variable too; it is still hard-coded in mobile_pt.sh. --> |
| `address already in use` on a portal, Burp, MCP, or MobSF port | Another process holds the port | Find it with `ss -ltnp \| grep -E ':(8811\|8080\|9876\|8000)\b'`. Stop it, or change the port in config. |
| Frida attach fails on an app | Framework or obfuscation the scripts do not cover, or a native pinning layer | Check the job log. For a single APK the portal may fall back to a static patch. Split uploads cannot fall back. |

## Security and legal

- **Only test apps you own, or apps you are authorized to test in writing.** This tool bypasses
  certificate pinning and intercepts traffic. Using it on apps or services you do not have
  permission to test may be illegal in your jurisdiction.
- Do not point the portal or Burp at production user data beyond the scope you were given.
- Keep `.env`, the Burp REST API key (Pro only), and the MobSF API key out of version control -
  the repo's `.gitignore` already excludes `.env`.
- Keep the portal, the Burp proxy, and the MCP server on `127.0.0.1` unless you need a LAN
  connection. See [Network interface choice](#network-interface-choice).
- Report security issues privately. <!-- TODO: add a SECURITY.md or contact address. -->

## Configuration

`install_mobile_pt.sh` and `portal/setup.sh` together write every value below into one repo-root
`.env`. To do it by hand instead: copy `.env.sample` to `.env` and fill in each value - every
variable is documented there, with where to get it and an example placeholder. That file is the
reference; this README does not duplicate it.

## License

This repository is MIT-licensed (see `LICENSE`). `portal/scripts/frida/` is **not** vendored here:
`portal/setup.sh` fetches it at install time from
[httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning)
(AGPL-3.0-or-later) into a gitignored directory, so this repo's own license isn't affected by it.
If you redistribute those fetched scripts separately, keep their own `LICENSE` file alongside them.
