import QtQuick
import Quickshell
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "ben.omafind"
  ipcTarget: "ben.omafind"
  manageIpc: false

  // App whose full host list is expanded in the popup.
  property string expanded: ""

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.6)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property string glyph: "󰒃"
  readonly property string alertGlyph: "󰒙"

  readonly property var sharedService: bar && bar.shell && typeof bar.shell.serviceFor === "function"
    ? bar.shell.serviceFor(moduleName) : null
  readonly property var service: sharedService || localService

  function pushSettings() { if (service) service.settings = settings }
  onSettingsChanged: pushSettings()
  onServiceChanged: pushSettings()
  Component.onCompleted: pushSettings()

  function hostLabel(h) {
    return (h.inbound ? "← " : "→ ") + h.host + ":" + h.port + (h.proto === "udp" ? " udp" : "")
      + (h.count > 1 ? "  ×" + h.count : "")
  }

  function summary(app) {
    if (app.connections === 0) return app.denied ? "Not running" : "No open connections"
    var names = []
    for (var i = 0; i < app.hosts.length && names.length < 2; i++) {
      if (names.indexOf(app.hosts[i].host) < 0) names.push(app.hosts[i].host)
    }
    var more = app.hosts.length - names.length
    return names.join(", ") + (more > 0 ? " +" + more : "")
  }

  function status(app) {
    if (app.blocked) return "BLOCKED"
    if (app.unblockable) return "DENIED · not isolated"
    if (app.denied) return "DENIED"
    if (app.new) return "NEW"
    return ""
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: {
    if (!opened) { expanded = ""; return }
    Qt.callLater(function() { if (keyCatcher) keyCatcher.forceActiveFocus() })
  }

  Service {
    id: localService
    active: root.sharedService === null
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: service.newApps > 0 && !vertical ? root.alertGlyph + " " + service.newApps : (service.newApps > 0 ? root.alertGlyph : root.glyph)
    slotSize: Style.bar.iconSlot * (service.newApps > 0 && !vertical ? 1.8 : 1)
    active: service.newApps > 0 || service.firewallProblem
    useActiveColor: active
    tooltipText: service.connections + " connection" + (service.connections === 1 ? "" : "s")
      + (service.newApps > 0 ? " · " + service.newApps + " new app" + (service.newApps === 1 ? "" : "s") : "")
    onPressed: function(b) {
      if (b === Qt.RightButton) { service.reviewAll(); return }
      root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(440))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(640))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      Flickable {
        id: flick
        anchors.fill: parent
        clip: true
        contentWidth: width
        contentHeight: column.implicitHeight
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height

        Column {
          id: column
          width: flick.width
          spacing: Style.space(12)

          PanelHero {
            title: "Network"
            meta: !service.running
              ? "omafind isn't running" + (service.lastError ? " · " + service.lastError : "")
              : service.connections + " connection" + (service.connections === 1 ? "" : "s")
                + " · " + (service.snapshot.activeApps || 0) + " apps"
                + (service.newApps > 0 ? " · " + service.newApps + " new" : "")
            foreground: root.foreground
            fontFamily: root.fontFamily
            iconComponent: Component {
              Text {
                textFormat: Text.PlainText
                text: service.newApps > 0 ? root.alertGlyph : root.glyph
                color: service.newApps > 0 ? root.urgent : root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.display
              }
            }
            trailingControl: Component {
              Button {
                visible: service.newApps > 0
                text: "Reviewed"
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: service.reviewAll()
              }
            }
          }

          Text {
            visible: service.firewallProblem
            width: parent.width
            wrapMode: Text.Wrap
            textFormat: Text.PlainText
            text: "Blocking " + service.firewall
            color: root.urgent
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          PanelSeparator { foreground: root.foreground }

          Text {
            visible: service.apps.length === 0
            text: "Nothing is talking to the network."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
          }

          Repeater {
            model: service.apps
            delegate: Item {
              id: row
              required property var modelData
              readonly property var app: modelData
              readonly property bool isOpen: root.expanded === app.name
              readonly property string badge: root.status(app)

              width: column.width
              implicitHeight: rowColumn.implicitHeight + Style.space(8)

              MouseArea {
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                  root.expanded = row.isOpen ? "" : row.app.name
                  if (row.app.new) service.review(row.app.name)
                }
              }

              Rectangle {
                anchors.fill: parent
                radius: Style.cornerRadius
                color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, row.isOpen ? 0.06 : 0)
              }

              Column {
                id: rowColumn
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.margins: Style.space(4)
                spacing: Style.space(2)

                Item {
                  width: parent.width
                  implicitHeight: Math.max(labels.implicitHeight, action.implicitHeight)

                  Column {
                    id: labels
                    anchors.left: parent.left
                    anchors.right: action.left
                    anchors.rightMargin: Style.space(10)
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(1)

                    Row {
                      spacing: Style.space(8)
                      Text {
                        textFormat: Text.PlainText
                        text: row.app.name + (row.app.system ? " (system)" : "")
                        color: row.app.blocked ? root.dim : root.foreground
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.body
                        font.bold: true
                        font.strikeout: row.app.blocked
                      }
                      Text {
                        visible: row.badge !== ""
                        textFormat: Text.PlainText
                        text: row.badge
                        color: row.app.new && !row.app.denied ? Color.accent : root.urgent
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: true
                        anchors.verticalCenter: parent.verticalCenter
                      }
                      Text {
                        visible: row.app.connections > 0
                        textFormat: Text.PlainText
                        text: String(row.app.connections)
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        anchors.verticalCenter: parent.verticalCenter
                      }
                    }

                    Text {
                      visible: !row.isOpen
                      width: parent.width
                      textFormat: Text.PlainText
                      text: root.summary(row.app)
                      color: root.dim
                      elide: Text.ElideRight
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                  }

                  Button {
                    id: action
                    visible: !row.app.system
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    text: row.app.denied ? "Allow" : "Block"
                    foreground: row.app.denied ? root.foreground : root.urgent
                    fontFamily: root.fontFamily
                    onClicked: row.app.denied ? service.allow(row.app.name) : service.deny(row.app.name)
                  }
                }

                Repeater {
                  model: row.isOpen ? row.app.hosts : []
                  delegate: Text {
                    required property var modelData
                    width: rowColumn.width
                    textFormat: Text.PlainText
                    text: root.hostLabel(modelData)
                    color: root.foreground
                    elide: Text.ElideMiddle
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }

                Text {
                  visible: row.isOpen && row.app.recent.length > 0
                  topPadding: Style.space(4)
                  textFormat: Text.PlainText
                  text: "Earlier"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }

                Repeater {
                  model: row.isOpen ? row.app.recent : []
                  delegate: Text {
                    required property var modelData
                    width: rowColumn.width
                    textFormat: Text.PlainText
                    text: "  " + modelData
                    color: root.dim
                    elide: Text.ElideMiddle
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }

                Text {
                  visible: row.isOpen && row.app.exe !== ""
                  width: rowColumn.width
                  topPadding: Style.space(4)
                  textFormat: Text.PlainText
                  text: row.app.exe + (row.app.pids.length ? "  · pid " + row.app.pids.join(", ") : "")
                  color: root.dim
                  elide: Text.ElideMiddle
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                Text {
                  visible: row.isOpen && row.app.unblockable
                  width: rowColumn.width
                  wrapMode: Text.Wrap
                  textFormat: Text.PlainText
                  text: "Runs inside another app's scope (e.g. a terminal), so blocking it would cut that app off too. Launch it from the app launcher to block it."
                  color: root.urgent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }
              }
            }
          }

          PanelSeparator { foreground: root.foreground }

          Toggle {
            width: parent.width
            label: "Alert on new apps"
            description: "Notify the first time an app connects, with Allow / Block"
            checked: service.notifyNewApps
            foreground: root.foreground
            fontFamily: root.fontFamily
            onClicked: service.setNotify(!service.notifyNewApps)
          }
        }
      }
    }
  }
}
