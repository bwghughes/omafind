# omafind

A small Little Snitch–style network monitor for the Omarchy bar, written in Rust.

- **See** which apps have connections open right now, and where they go (reverse DNS, inbound ← / outbound →).
- **Get told** the first time an app connects anywhere. The notification has **Allow** / **Block** buttons.
- **Block** an app with one click. Blocking uses nftables and applies to that app's systemd scope.

## Install

```sh
./install.sh
```

The installer builds a release binary and installs it root-owned at `/usr/local/bin/omafind`. It adds a sudoers rule so the daemon can run `omafind firewall …` without a password, copies the plugin to `~/.config/omarchy/plugins/ben.omafind`, and places the widget in the bar next to the network icon.

To remove everything, run `./install.sh --uninstall`. Your rules are kept.

## Bar widget

| | |
|---|---|
| 󰒃 | Nothing new |
| 󰒙 3 | 3 apps you haven't reviewed have connections open |
| Left click | Open the panel: each app, its hosts, and a Block/Allow button. Click an app for details |
| Right click | Mark everything reviewed |

## CLI

```
omafind list [--json]       current connections
omafind watch               JSON snapshot stream (the bar plugin runs this)
omafind deny|allow <app>    block / unblock
omafind review <app>|--all  clear the NEW flag
omafind notify on|off
omafind rules
```

Rules are stored in `~/.config/omafind/rules.json`. You can edit this file by hand, and the daemon reloads it on change. The history of apps seen and their recent hosts is kept in `~/.local/state/omafind/seen.json`.

## How it works

- Every tick (1s by default), the daemon reads `/proc/net/{tcp,tcp6,udp,udp6}` and maps each socket inode to a process through `/proc/<pid>/fd`.
- Processes are then named as apps:
  - Chromium/Electron helper processes fold into their parent browser.
  - Interpreters such as python, node, and electron are named after the script they run.
- Sockets owned by other users (root, systemd-resolved, …) can't be traced to a process without root. They are listed under that user's name as *system*.
- To block an app, the daemon finds every `app-*.scope` in your `app.slice` that belongs to it. The root helper then loads this table:

  ```
  table inet omafind { chain output { … socket cgroupv2 level 5 "<scope>" reject } }
  ```

  The helper only accepts `app-*.scope` paths in the invoking user's own `app.slice`. The table is re-synced whenever a denied app starts in a new scope.

## Limitations

- **Polling misses short connections.** A connection that opens and closes between two ticks is never seen.
- **Blocking starts late.** A newly launched denied app gets up to one tick of network access before its scope is blocked.
- **Apps sharing a terminal's scope can't be blocked.** An app started from a terminal (e.g. `curl`) runs inside the terminal's scope. Blocking it would cut off the whole terminal, so omafind refuses and marks it *DENIED · not isolated*. Apps started from the launcher get their own scope and block fine.
- **Hostnames come from reverse DNS.** omafind does not see the name the app actually looked up, so CDNs often show up as their provider's hostname.
