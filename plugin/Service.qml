import QtQuick
import Quickshell
import Quickshell.Io

// Runs `omafind watch` for as long as the shell lives and exposes its latest
// snapshot. All rule changes go through the omafind CLI, which edits
// ~/.config/omafind/rules.json; the daemon picks them up on its next tick.
Item {
  id: root

  property var shell: null
  property var manifest: null
  property var settings: ({})
  property bool active: true

  readonly property string binary: String(setting("binary", "/usr/local/bin/omafind"))
  readonly property int interval: Math.max(250, parseInt(setting("interval", 1000), 10) || 1000)
  readonly property bool showSystem: setting("showSystem", true) !== false

  property var snapshot: ({ apps: [], connections: 0, activeApps: 0, newApps: 0, firewall: "idle", notifyNewApps: true })
  property bool running: false
  property string lastError: ""

  readonly property var apps: {
    var list = snapshot.apps || []
    if (showSystem) return list
    return list.filter(function(a) { return !a.system })
  }
  readonly property int connections: snapshot.connections || 0
  readonly property int newApps: snapshot.newApps || 0
  readonly property string firewall: snapshot.firewall || "idle"
  readonly property bool firewallProblem: firewall.indexOf("unavailable") === 0
  readonly property bool notifyNewApps: snapshot.notifyNewApps !== false

  function setting(name, fallback) {
    var value = settings ? settings[name] : undefined
    return value === undefined || value === null ? fallback : value
  }

  function run(args) {
    Quickshell.execDetached([root.binary].concat(args))
  }

  function deny(app) { run(["deny", app]) }
  function allow(app) { run(["allow", app]) }
  function review(app) { run(["review", app]) }
  function reviewAll() { run(["review", "--all"]) }
  function setNotify(on) { run(["notify", on ? "on" : "off"]) }

  Process {
    id: watcher
    command: [root.binary, "watch", "--interval", String(root.interval)]
    running: root.active
    onRunningChanged: root.running = running
    stdout: SplitParser {
      onRead: function(line) {
        try {
          root.snapshot = JSON.parse(line)
          root.lastError = ""
        } catch (e) {}
      }
    }
    stderr: SplitParser {
      onRead: function(line) { root.lastError = String(line) }
    }
    onExited: function(code) {
      if (root.active) restartTimer.start()
    }
  }

  // Restart after a crash, or after the interval setting changes.
  onIntervalChanged: if (watcher.running) watcher.running = false

  Timer {
    id: restartTimer
    interval: 2000
    onTriggered: if (root.active) watcher.running = true
  }

  IpcHandler {
    enabled: root.active && root.shell !== null
    target: "ben.omafind"

    function open(): void { if (root.shell) root.shell.summon("ben.omafind") }
    function close(): void { if (root.shell) root.shell.hide("ben.omafind") }
    function toggle(): void { if (root.shell) root.shell.toggle("ben.omafind") }
    function status(): string { return JSON.stringify(root.snapshot) }
  }
}
