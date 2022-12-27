#!/bin/bash
############
## gconftool.sh
#############


['permissions','size','owner','group'. 'octal_permissions','mime_type']

gsettings set org.gnome.desktop.interface can-change-accels true



gconftool-2 --dump										# Dump to standard output an XML description of all
gconftool-2 --all-entries								# Print all key/value pairs in a directory
gconftool-2 --all-dirs										# Print all subdirectories in a directory.
gconftool-2 --recursive-list 							# Print all subdirectories and entries under a directpry
gconftool-2 --recursive-unset						# Recursively unset all keys at or below the key/directory
gconftool-2 --load											# Load from the specified file an XML description
gconftool-2 --get-list-element
gconftool-2 --get-list-size
gconftool-2 --search-key

gconftool-2 --set
gconftool-2 --get
gconftool-2 --unset


gconftool-2 --type string --set /org/gnome/terminal/keybindings/copy <Ctrl>c
gconftool-2 --type string --set /org/gnome/terminal/keybindings/paste <Ctrl>v
gconftool-2 --type string --set /org/gnome/terminal/keybindings/new-tab <Shift>n
gconftool-2 --type string --set /org/gnome/terminal/keybindings/next-tab <Ctrl>right
gconftool-2 --type string --set /org/gnome/terminal/keybindings/new-window <Shift>w
gconftool-2 --type bool --set /apps/gnome-terminal/profiles/Default/scrollback_unlimited true 			#Terminal -> Edit -> Profile Preferences -> Scrolling -> Scrollback: Unlimited -> Close
gconftool-2 --type bool --set /org/mate/terminal/profiles/Default/scrollback_unlimited true
gconftool-2 --type string --set /org/mate/terminal/global/default-profile Xe1phix
gconftool-2 --type string --set /org/mate/terminal/keybindings/copy <Ctrl>c
gconftool-2 --type string --set /org/mate/terminal/keybindings/paste <Ctrl>v
gconftool-2 --type string --set /org/mate/terminal/keybindings/new-tab <Shift>n
gconftool-2 --type string --set /org/mate/terminal/keybindings/next-tab <Ctrl>right
gconftool-2 --type string --set /org/mate/terminal/keybindings/new-window <Shift>w


gconftool-2 --type bool --set /org/gnome/desktop/media-handling/automount false
gconftool-2 --type bool --set /org/gnome/desktop/media-handling/automount-open false
gconftool-2 --type bool --set /org/gnome/desktop/media-handling/autorun-never true
gconftool-2 --type bool --set /org/mate/media-handling/automount false
gconftool-2 --type bool --set /org/mate/media-handling/automount-open false
gconftool-2 --type bool --set /org/mate/media-handling/autorun-never true
gconftool-2 --type string --set /org/mate/media-handling/autorun-x-content-ignore ['x-content/software']
gconftool-2 --type string --set /org/mate/SettingsDaemon/plugins/media-keys/next <Ctrl>Right
gconftool-2 --type string --set /org/mate/SettingsDaemon/plugins/media-keys/previous <Ctrl>Left
gconftool-2 --type string --set /org/mate/SettingsDaemon/plugins/media-keys/Volume-mute
gconftool-2 --type string --set /org/mate/SettingsDaemon/plugins/media-keys/Volume-down <Control>Down
gconftool-2 --type string --set /org/mate/SettingsDaemon/plugins/media-keys/Volume-up <Control>up



gconftool-2 --type bool --set /org/mate/Atril/Default/inverted-colors true

gconftool-2 --type bool --set /org/mate/system-monitor/show-tree true
gconftool-2 --type bool --set /org/mate/system-monitor/show-all-fs true
gconftool-2 --type bool --set /org/mate/system-monitor/proctree/col-1-visible true
gconftool-2 --type bool --set /org/mate/system-monitor/proctree/col-14-visible true
gconftool-2 --type bool --set /org/mate/system-monitor/proctree/col-3-visible true

gconftool-2 --type string --set /org/gnome/desktop/screensaver/Logout-command <Ctrl><Alt><Delete>
gconftool-2 --type bool --set /org/gnome/desktop/screensaver/idle-activation-enabled false
gconftool-2 --type bool --set /org/gnome/desktop/screensaver/lock-enabled false

gconftool-2 --type string --set /org/gnome/nautilus/icon-view/default-column-order ['permissions', 'name', 'size', 'owner', 'group', 'mime_type', 'octal_permissions']
gconftool-2 --type string --set /org/gnome/nautilus/icon-view/default-visible-columns ['permissions', 'name', 'size', 'owner', 'group', 'mime_type', 'octal_permissions']
gconftool-2 --type string --set /org/gnome/nautilus/list-view/default-column-order ['permissions', 'name', 'size', 'owner', 'group', 'mime_type', 'octal_permissions']
gconftool-2 --type string --set /org/gnome/nautilus/list-view/default-visible-columns ['permissions', 'name', 'size', 'owner', 'group', 'mime_type', 'octal_permissions']
gconftool-2 --type bool --set /org/gnome/nautilus/preferences/Show-advanced-permissions true
gconftool-2 --type bool --set /org/gnome/nautilus/preferences/show-hidden-files true
gconftool-2 --type bool --set /org/gnome/nautilus/preferences/enable-delete true

gconftool-2 --type bool --set /org/mate/caja-open-terminal/desktop-opens-home-dir true
gconftool-2 --type bool --set /org/mate/caja/preferences/Show-advanced-permissions true
gconftool-2 --type bool --set /org/mate/caja/preferences/show-hidden-files true
gconftool-2 --type bool --set /org/mate/caja/preferences/enable-delete true
gconftool-2 --type string --set /org/mate/caja/list-view/default-visible-columns ['permissions', 'name', 'size', 'owner', 'group', 'mime_type', 'octal_permissions']
gconftool-2 --type string --set /org/mate/caja/list-view/default-column-order ['permissions', 'name', 'size', 'owner', 'group', 'mime_type', 'octal_permissions']
gconftool-2 --type string --set /org/mate/caja/icon-view/default-visible-columns ['permissions', 'name', 'size', 'owner', 'group', 'mime_type', 'octal_permissions']
gconftool-2 --type string --set /org/mate/caja/icon-view/default-column-order ['permissions', 'name', 'size', 'owner', 'group', 'mime_type', 'octal_permissions']

org.mate.caja.icon-view captions ['permissions', 'name', 'size', 'owner', 'group', 'mime_type', 'octal_permissions']

gconftool-2 --type bool --set /org/mate/pluma/auto-save true
gconftool-2 --type bool --set /org/mate/pluma/Display-Line-Numbers true
gconftool-2 --type bool --set /org/mate/pluma/create-backup-copies true
gconftool-2 --type bool --set /org/mate/pluma/use-default-font false
gconftool-2 --type string --set /org/mate/pluma/wrap-mode GTK_WRAP_NONE
gconftool-2 --type bool --set /org/mate/pluma/highlight-current-line true



gconftool-2 --get /org/gnome/gedit/preferences/editor/auto-save-interval


gconftool-2 --type bool --set /org/gnome/gedit/preferences/editor/auto-save true
gconftool-2 --type bool --set /org/gnome/gedit/preferences/editor/create-backup-copy true
gconftool-2 --type bool --set /org/gnome/gedit/preferences/editor/highlight-current-line true
gconftool-2 --type bool --set /org/gnome/gedit/preferences/editor/syntax-highlighting true
gconftool-2 --type bool --set /org/gnome/gedit/preferences/editor/highlight-current-line true
gconftool-2 --type string --set /org/gnome/gedit/preferences/editor/wrap-last-split-mode GTK_WRAP_WORD
gconftool-2 --type string --set /org/gnome/gedit/preferences/editor/wrap-mode 'none'
gconftool-2 --type string --set /org/gnome/gedit/preferences/editor/auto-save-interval 1


gconftool-2 --type bool --set /org/mate/FileSharing/bluetooth-enabled false
gconftool-2 --type bool --set /org/mate/FileSharing/bluetooth-allow-write false
gconftool-2 --type bool --set /org/mate/FileSharing/bluetooth-accept-files ask
gconftool-2 --type bool --set /org/mate/FileSharing/bluetooth-notify true
gconftool-2 --type bool --set /org/mate/FileSharing/enabled false
gconftool-2 --type bool --set /org/mate/FileSharing/Bluetooth-ObexPush-enabled false
gconftool-2 --type string --set /org/mate/FileSharing/require-password always


gconftool-2 --type bool --set /org/mate/system-log/filters ['/var/log/auth.log', '/var/log/daemon.log', '/var/log/kern.log', '/var/log/user.log', '/var/log/debug', '/var/log/syslog', '/var/log/wtmp', '/var/log/btmp', '/var/log/lastlog', '/var/log/tiger', '/var/log/chkrootkit', '/var/log/rkhunter',  '/var/log/ufw.log', '/var/log/apache/access.log', '/var/log/mail.log', '/var/log/pycentral.log', '/var/log/bootstrap.log', '/var/log/pm-powersave.log', '/var/log/Xorg.log', '/var/log/Xorg.0.log', '/var/log/alternatives.log', '/var/log/mail.info', '/var/log/mail.err', '/var/log/mail.warn', '/var/log/dpkg.log']
gconftool-2 --type string --set /org/mate/system-log/filters '/var/log/auth.log /var/log/daemon.log /var/log/kern.log', '/var/log/user.log', '/var/log/debug', '/var/log/syslog', '/var/log/wtmp', '/var/log/btmp', '/var/log/lastlog', '/var/log/tiger', '/var/log/chkrootkit', '/var/log/rkhunter',  '/var/log/ufw.log', '/var/log/apache/access.log', '/var/log/mail.log', '/var/log/pycentral.log', '/var/log/bootstrap.log', '/var/log/pm-powersave.log', '/var/log/Xorg.log', '/var/log/Xorg.0.log', '/var/log/alternatives.log', '/var/log/mail.info', '/var/log/mail.err', '/var/log/mail.warn', '/var/log/dpkg.log'
gconftool-2 --type string --set /org/mate/system-log/filters '/var/log/auth.log /var/log/daemon.log /var/log/kern.log /var/log/user.log /var/log/debug /var/log/syslog /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/tiger /var/log/chkrootkit /var/log/rkhunter /var/log/ufw.log /var/log/apache/access.log /var/log/mail.log /var/log/alternatives.log /var/log/mail.info /var/log/mail.err /var/log/mail.warn /var/log/dpkg.log'
gconftool-2 --type string --set /org/mate/system-log/filters auth,authpriv.*

gconftool-2 --type string --set /org/gnome/brasero/config/checksum-files 2
gconftool-2 --type string --set /org/gnome/brasero/config/checksum-image 2
gconftool-2 --type string --set /org/gnome/brasero/config/plugins ['image-checksum', 'file-checksum']


gconftool-2 --type bool --set /org/gnome/seahorse/manager/sidebar-visible true
gconftool-2 --type string --set /org/gnome/seahorse/manager/keyrings-selected x-hkp://pool/sks-keyservers/net
gconftool-2 --type string --set /org/gnome/seahorse/server-publish-to x-hkp://pool/sks-keyservers/net
gconftool-2 --type string --set /org/gnome/crypto/pgp/key-servers ['x-hkp://pool/sks-keyservers/net']
gconftool-2 --type bool --set /org/gnome/crypto/pgp/ascii-armor true
gconftool-2 --type string --set /org/gnome/seahorse/item-filter all
gconftool-2 --type bool --set /org/gnome/crypto/cache/gpg-cache-Authorize true



org.mate.mate-menu.plugins.applications enable-google false
org.mate.mate-menu.plugins.applications enable-wikipedia false
org.mate.mate-menu.plugins.applications enable-dictionary false
org.mate.mate-menu.plugins.places show-gtk-bookmarks true
org.mate.mate-menu.plugins.places show-desktop false
org.mate.mate-menu.plugins.places show-network false

org.mate.panel locked-down false

org.mate.caja-open-terminal desktop-opens-home-dir true

org.mate.caja.desktop network-icon-visible false

org.mate.caja.preferences desktop-is-home-dir true
org.mate.caja.preferences executable-text-activation 'display'


org.cinnamon.desktop.lockdown disable-printing true
org.cinnamon.desktop.lockdown disable-print-setup true

org.cinnamon.desktop.media-handling automount false
org.cinnamon.desktop.media-handling automount-open false
org.gnome.settings-daemon.plugins.print-notifications active false
org.gnome.nm-applet show-applet false
org.gnome.Terminal.Legacy.Settings new-terminal-mode 'tab'
org.mate.pluma auto-save true
org.mate.pluma auto-save-interval 3
org.mate.pluma color-scheme 'cobalt'
org.mate.pluma create-backup-copy true
org.mate.pluma max-recents 20
org.mate.pluma print-wrap-mode 'GTK_WRAP_NONE'
org.mate.pluma writable-vfs-schemes ['dav', 'davs']

org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ close-tab '<Alt>q'
org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ close-window '<Ctrl>q'
org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ copy '<Ctrl>c'
org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ detach-tab '<Ctrl>d'
org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ find '<Ctrl>f'
org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ find-clear '<Control><Shift>x'
org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ find-next '<Ctrl>s'
org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ find-previous '<Ctrl>w'
org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ new-tab '<Ctrl>t'
org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ new-window '<Ctrl>w'
org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ paste '<Ctrl>v'
org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ select-all '<Ctrl>a'
org.gnome.Vino authentication-methods ['vnc']
org.gnome.desktop.privacy hide-identity true
org.gnome.desktop.privacy recent-files-max-age 7
org.mate.applications-browser nremote false
org.mate.applications-browser exec 'firefox-esr'
org.mate.eom.ui image-collection-position 'left'
org.mate.eom.ui image-collection-resizable true
org.mate.eom.ui sidebar true
org.mate.screensaver idle-activation-enabled false
org.mate.screensaver lock-delay 1
org.mate.screensaver lock-enabled true
org.mate.screensaver themes ['screensavers-cosmos-slideshow']
org.mate.screensaver user-switch-enabled false

org.mate.screenshot last-save-directory ''

org.mate.terminal.global default-profile 'Xe1phix'
org.mate.terminal.global ctrl-tab-switch-tabs true
org.mate.lockdown disable-printing true
org.mate.lockdown disable-print-setup true

org.gnome.Vino view-only true
apps.gtkhash hash-functions ['SHA1', 'SHA256', 'SHA512']
apps.gtkhash-properties hash-functions ['SHA1', 'SHA256', 'SHA512']
org.gnome.crypto.pgp keyservers ['hkp://pool.sks-keyservers.net']
org.gnome.crypto.pgp default-key ''

org.virt-manager.virt-manager.stats enable-net-poll true
org.virt-manager.virt-manager.stats enable-memory-poll true


gconftool-2 --type bool --set /org/mate/panel/locked-down true
gconftool-2 --type bool --set /org/mate/search-tool/select/show-hidden-files-and-folders true
gconftool-2 --type bool --set /org/gnome/desktop/lockdown/Disable-print-setup true
gconftool-2 --type bool --set /org/gnome/desktop/lockdown/Disable-printing true
gconftool-2 --type bool --set /org/gnome/desktop/lockdown/Disable-save-to disk true
gconftool-2 --type bool --set /org/gnome/desktop/lockdown/Disable-user-switching true
gconftool-2 --type bool --set /org/mate/lockdown/disable-application-handlers true
gconftool-2 --type bool --set /org/mate/lockdown/Disable-print-setup true
gconftool-2 --type bool --set /org/mate/lockdown/Disable-printing true
gconftool-2 --type bool --set /org/mate/lockdown/Disable-save-to disk true
gconftool-2 --type bool --set /org/mate/lockdown/Disable-user-switching true
gconftool-2 --type bool --set /org/mate/lockdown/disable-application-handlers true
gconftool-2 --type bool --set /org/gnome/desktop/interface/clock-show-seconds true


gconftool-2 --type bool --set /org/gnome/desktop/interface/clock-show-seconds true

gconftool-2 --type bool --set /org/mate/pluma/plugins/filebrowser/on-load/enable-remote false

gconftool-2 --type string --set /org/gnome/system/smb/workgroup Faggot
gconftool-2 --type string --set /org/gnome/system/proxy/socks/host 127.0.0.1
gconftool-2 --type string --set /org/gnome/system/proxy/socks/port 9050
gconftool-2 --type bool --set /org/gnome/system/proxy/http/use-authentication true
gconftool-2 --type string --set /org/gnome/system/proxy/http/host 127.0.0.1
gconftool-2 --type string --set /org/gnome/system/proxy/http/port 4444 

gconftool-2 --type bool --set /org/mate/applications-browser/nremote disable

gconftool-2 --type bool --set /org/mate/engrampa/general/Encrypt-header true
gconftool-2 --type bool --set /org/mate/engrampa/general/encrypt-header true
gconftool-2 --type string --set /org/mate/engrampa/dialogs/batch-add/default-extension .7z

gconftool-2 --type bool --set /org/mate/Atril/Default/inverted-colors true



gconftool-2 --type string --set /org/mate/keybindings/custom1/action gksu /usr/bin/x-terminal-emulator
gconftool-2 --type string --set /org/mate/keybindings/custom1/binding <Shift>r
gconftool-2 --type string --set /org/mate/keybindings/custom1/name Root Terminal

gconftool-2 --type string --set /org/mate/keybindings/screenreader/action mateconftool-2 --toggle /desktop/mate/applications/at/screen_reader_enabled
gconftool-2 --type string --set /org/mate/keybindings/screenreader/binding <ctrl><Shift>r
gconftool-2 --type string --set /org/mate/keybindings/screenreader/name Toggle screen reader


gconftool-2 --type string --set /org/mate/keybindings/custom4/action gksu /usr/bin/gdebi-gtk %f
gconftool-2 --type string --set /org/mate/keybindings/custom4/binding <Alt>g
gconftool-2 --type string --set /org/mate/keybindings/custom4/name GDebi Package Installer {Super User}

gconftool-2 --type string --set /org/mate/keybindings/custom3/action gksu /usr/bin/gdebi-gtk %f
gconftool-2 --type string --set /org/mate/keybindings/custom3/binding <Alt>g
gconftool-2 --type string --set /org/mate/keybindings/custom3/name GDebi Package Installer {Super User}

gconftool-2 --type string --set /org/mate/keybindings/custom/action /usr/bin/seahorse
gconftool-2 --type string --set /org/mate/keybindings/custom/binding <Shift>s
gconftool-2 --type string --set /org/mate/keybindings/custom/name Seahorse 


gconftool-2 --type string --set /org/mate/keybindings/custom2/action gksu /usr/bin/seahorse
gconftool-2 --type string --set /org/mate/keybindings/custom2/binding <Primary><Shift>s
gconftool-2 --type string --set /org/mate/keybindings/custom2/name Seahorse {SuperUser}


gconftool-2 --type string --set /org/mate/keybindings/custom5/action gksu /usr/bin/mate-system-log
gconftool-2 --type string --set /org/mate/keybindings/custom5/binding <Primary><Shift>l
gconftool-2 --type string --set /org/mate/keybindings/custom5/name Log File Viewer {SuperUser}


gconftool-2 --type string --set /org/mate/keybindings/custom6/action gksu /usr/bin/mate-system-monitor
gconftool-2 --type string --set /org/mate/keybindings/custom6/binding <Primary><Alt>m
gconftool-2 --type string --set /org/mate/keybindings/custom6/name MATE System Monitor {SuperUser}

gconftool-2 --type string --set /org/mate/keybindings/custom/action gksu /usr/bin/caja
gconftool-2 --type string --set /org/mate/keybindings/custom/binding <Primary><Alt>n
gconftool-2 --type string --set /org/mate/keybindings/custom/name caja {SuperUser}


gconftool-2 --type string --set /org/mate/keybindings/custom/action gksu /usr/bin/pluma 
gconftool-2 --type string --set /org/mate/keybindings/custom/binding <Primary><Shift>p
gconftool-2 --type string --set /org/mate/keybindings/custom/name pluma Text Editor {SuperUser}

gconftool-2 --type string --set /org/mate/keybindings/custom/action /usr/bin/pluma %U
gconftool-2 --type string --set /org/mate/keybindings/custom/binding <Shift>p
gconftool-2 --type string --set /org/mate/keybindings/custom/name pluma Text Editor


gconftool-2 --type string --set /org/mate/keybindings/custom/action mate-screenshot --interactive
gconftool-2 --type string --set /org/mate/keybindings/custom/binding <Shift>Print
gconftool-2 --type string --set /org/mate/keybindings/custom/name screenshot


gconftool-2 --type string --set /org/mate/keybindings/custom/action gksu /usr/sbin/tiger -e
gconftool-2 --type string --set /org/mate/keybindings/custom/binding <Primary><Alt>t
gconftool-2 --type string --set /org/mate/keybindings/custom/name Tiger UNIX Security Tool {SuperUser}

gconftool-2 --type string --set /org/mate/keybindings/custom/action gksu /usr/bin/mc
gconftool-2 --type string --set /org/mate/keybindings/custom/binding <Primary><Shift>m
gconftool-2 --type string --set /org/mate/keybindings/custom/name Midnight Commander {SuperUser}




gconftool-2 --type string --set /org/mate/keybindings/custom/action gksu /usr/bin/lynis --checkall --nocolors --logfile /var/log/Lynis/lynis-Log.txt
gconftool-2 --type string --set /org/mate/keybindings/custom/binding <ctrl>l
gconftool-2 --type string --set /org/mate/keybindings/custom/name Lynis Auditing Tool Checkall nocolors {Super User}


gconftool-2 --type string --set /org/mate/keybindings/custom/action gksu /usr/sbin/chkrootkit -d -x 
gconftool-2 --type string --set /org/mate/keybindings/custom/binding 
gconftool-2 --type string --set /org/mate/keybindings/custom/name 


gconftool-2 --type string --set /org/mate/keybindings/custom/action 
gconftool-2 --type string --set /org/mate/keybindings/custom/binding 
gconftool-2 --type string --set /org/mate/keybindings/custom/name 


gconftool-2 --type string --set /org/mate/keybindings/custom/action 
gconftool-2 --type string --set /org/mate/keybindings/custom/binding 
gconftool-2 --type string --set /org/mate/keybindings/custom/name 


gconftool-2 --type string --set /org/mate/keybindings/custom/action 
gconftool-2 --type string --set /org/mate/keybindings/custom/binding 
gconftool-2 --type string --set /org/mate/keybindings/custom/name 



gconftool-2 --type bool --set /org/mate/engrampa/general/
gconftool-2 --type bool --set /org/mate/engrampa/general/



gconftool-2 --type bool --set /org/gnome/Empathy/autoconnect false
gconftool-2 --type bool --set /org/gnome/Empathy/location/publish false
gconftool-2 --type bool --set /org/gnome/Empathy/location/resource-cell false
gconftool-2 --type bool --set /org/gnome/Empathy/location/resource-gps false
gconftool-2 --type bool --set /org/gnome/Empathy/location/resource-network false
gconftool-2 --type bool --set /org/gnome/Empathy/notifications/notifications-enabled false
gconftool-2 --type bool --set /org/gnome/Empathy/sounds/sounds-enabled false
gconftool-2 --type bool --set /org/gnome/Empathy/ui/events-notify-area false
gconftool-2 --type bool --set /org/gnome/evolution/eds-shell/Start-offline enabled
gconftool-2 --type bool --set /org/gnome/evolution/shell/network-config/use-authentication true


gconftool-2 --type bool --set /org/gnome/Vino/enabled false
gconftool-2 --type bool --set /org/gnome/Vino/require-encryption true
gconftool-2 --type bool --set /org/gnome/Vino/view-only true
gconftool-2 --type bool --set /org/gnome/Vino/disable-background true
gconftool-2 --type bool --set /org/gnome/Vino/authentication-methods vnc
gconftool-2 --type bool --set /org/gnome/Vino/disable-XDamage true
gconftool-2 --type bool --set /org/gnome/Vino/Notify-on-connect true
gconftool-2 --type bool --set /org/gnome/Vino/Prompt-enabled true
gconftool-2 --type bool --set /org/gnome/Vino/use-UPNP false


gconftool-2 --type bool --set /org/yorba/shotwell/plugins/enable-state false
gconftool-2 --type bool --set /org/yorba/shotwell/plugins/publishing-facebook false
gconftool-2 --type bool --set /org/yorba/shotwell/plugins/publishing-flickr false
gconftool-2 --type bool --set /org/yorba/shotwell/plugins/publishing-picasa false
gconftool-2 --type bool --set /org/yorba/shotwell/plugins/publishing-piwigo false
gconftool-2 --type bool --set /org/yorba/shotwell/plugins/publishing-Yandex-Fotki false 
gconftool-2 --type bool --set /org/yorba/shotwell/plugins/publishing-youtube false
gconftool-2 --type bool --set /org/yorba/shotwell/plugins/transitions-crumble false 
gconftool-2 --type bool --set /org/yorba/shotwell/plugins/transitions-fade false
gconftool-2 --type bool --set /org/yorba/shotwell/plugins/transitions-slide false




gconftool-2 --type string --set net.sf.liferea browser 'firejail --seccomp --name=firefox --caps.drop=all --nonewprivs --private --private-tmp --shell=none --read-only=~/.mozilla --profile=/etc/firejail/firefox-common.profile /usr/bin/firefox-esr -new-tab https://boards.4chan.org/b/'
gconftool-2 --type bool --set net.sf.liferea disable-javascript true
gconftool-2 --type bool --set net.sf.liferea do-not-track true
gconftool-2 --type string --set net.sf.liferea download-tool 2
gconftool-2 --type bool --set org.gnome.Evince.Default inverted-colors true
gconftool-2 --type string --set org.gnome.desktop.interface clock-format '12h'
gconftool-2 --type bool --set org.gnome.desktop.interface clock-show-date true
gconftool-2 --type bool --set org.gnome.desktop.interface clock-show-weekday true
gconftool-2 --type bool --set org.gnome.evolution.eds-shell start-offline true
gconftool-2 --type bool --set org.mate.caja.preferences show-hidden-files true
gconftool-2 --type string --set org.gnome.desktop.privacy recent-files-max-age -1
gconftool-2 --type bool --set org.gnome.desktop.search-providers disable-external true
gconftool-2 --type bool --set org.gnome.desktop.sound allow-volume-above-100-percent true
gconftool-2 --type bool --set org.gnome.desktop.lockdown disable-print-setup true
gconftool-2 --type bool --set org.gnome.desktop.lockdown disable-printing true
gconftool-2 --type bool --set org.gnome.settings-daemon.plugins.sharing active false

gconftool-2 --type string --set org.mate.caja.icon-view captions ['name', 'size', 'owner', 'type', 'mime_type', 'octal_permissions', 'permissions', 'location']
gconftool-2 --type string --set org.mate.caja.list-view default-column-order ['name', 'size', 'owner', 'type', 'mime_type', 'octal_permissions', 'permissions', 'location']
gconftool-2 --type string --set org.mate.caja.list-view default-visible-columns ['name', 'size', 'owner', 'type', 'mime_type', 'octal_permissions', 'permissions', 'location']
gconftool-2 --type string --set org.mate.caja.list-view default-zoom-level 'large'

gconftool-2 --type bool --set /org/gnome/Vinagre/shared-flag/enable-browsing false
gconftool-2 --type bool --set /org/gnome/rhythmbox/sharing/enable-sharing false
gconftool-2 --type bool --set /org/gnome/rhythmbox/sharing/require-password true
gconftool-2 --type bool --set /org/gnome/rhythmbox/podcast/download-interval manual
gconftool-2 --type bool --set /org/gnome/Vinagre/always-enable-listening false
rm /usr/share/glib-2.0/schemas/org.mate.weather.gschema.xml
rm org.yorba.shotwell-extras.gschema.xml
rm org.yorba.shotwell.gschema.xml


org.gnome.settings-daemon.plugins.sharing active false

net.sf.liferea browser 'firejail --seccomp --name=firefox --caps.drop=all --nonewprivs --private --private-tmp --shell=none --read-only=~/.mozilla --profile=/etc/firejail/firefox-common.profile /usr/bin/firefox-esr -new-tab https://boards.4chan.org/b/'

net.sf.liferea disable-javascript true

net.sf.liferea do-not-track true

net.sf.liferea download-tool 2

org.gnome.Evince.Default inverted-colors true



org.gnome.desktop.interface clock-format '12h'
org.gnome.desktop.interface clock-show-date true
org.gnome.desktop.interface clock-show-weekday true

org.gnome.evolution.eds-shell start-offline true




org.mate.caja.preferences show-hidden-files true
org.gnome.desktop.privacy recent-files-max-age -1
org.gnome.desktop.search-providers disable-external true
org.gnome.desktop.sound allow-volume-above-100-percent true
org.gnome.desktop.lockdown disable-print-setup true
org.gnome.desktop.lockdown disable-printing true

org.mate.caja.icon-view captions ['name', 'size', 'owner', 'type', 'mime_type', 'octal_permissions', 'permissions', 'location']
org.mate.caja.list-view default-column-order ['name', 'size', 'owner', 'type', 'mime_type', 'octal_permissions', 'permissions', 'location']
org.mate.caja.list-view default-visible-columns ['name', 'size', 'owner', 'type', 'mime_type', 'octal_permissions', 'permissions', 'location']
org.mate.caja.list-view default-zoom-level 'large'


org.gnome.brasero.config checksum-files 2
org.gnome.brasero.config checksum-image 2
org.gnome.brasero.config plugins ['file-checksum', 'normalize', 'burn-uri', 'image-checksum']

org.gnome.brasero nautilus-extension-debug true

/org/gnome/brasero/plugins/file-downloader/priority 0


/root/.gconf/apps/%gconf.xml
/root/.gconf/apps/gnome-terminal/%gconf.xml
/root/.gconf/apps/gnome-terminal/keybindings/%gconf.xml
/root/.gconf/apps/gnome-terminal/profiles/%gconf.xml
/root/.gconf/apps/gnome-terminal/profiles/Default/%gconf.xml
/root/.gconf/apps/nm-applet/%gconf.xml
/etc/gconf/gconf.xml.defaults
/etc/gconf/gconf.xml.mandatory
/etc/gconf/gconf.xml.defaults/%gconf-tree.xml
/etc/gconf/gconf.xml.mandatory/%gconf-tree.xml
/etc/skel/.gconf/apps/%gconf.xml
/etc/skel/.gconf/apps/gnome-terminal/%gconf.xml
/etc/skel/.gconf/apps/gnome-terminal/profiles/%gconf.xml
/etc/skel/.gconf/apps/gnome-terminal/profiles/Default/%gconf.xml
/home/poozer/.gconf/apps/%gconf.xml
/home/poozer/.gconf/apps/gksu/%gconf.xml
/home/poozer/.gconf/apps/gnome-terminal/%gconf.xml
/home/poozer/.gconf/apps/gnome-terminal/profiles/%gconf.xml
/home/poozer/.gconf/apps/gnome-terminal/profiles/Default/%gconf.xml


/lib/live/mount/rootfs/filesystem.squashfs/etc/gconf/gconf.xml.defaults
/lib/live/mount/rootfs/filesystem.squashfs/etc/gconf/gconf.xml.mandatory
/lib/live/mount/rootfs/filesystem.squashfs/etc/gconf/gconf.xml.defaults/%gconf-tree.xml
/lib/live/mount/rootfs/filesystem.squashfs/etc/gconf/gconf.xml.mandatory/%gconf-tree.xml
/lib/live/mount/rootfs/filesystem.squashfs/etc/skel/.gconf/apps/%gconf.xml
/lib/live/mount/rootfs/filesystem.squashfs/etc/skel/.gconf/apps/gnome-terminal/%gconf.xml
/lib/live/mount/rootfs/filesystem.squashfs/etc/skel/.gconf/apps/gnome-terminal/profiles/%gconf.xml
/lib/live/mount/rootfs/filesystem.squashfs/etc/skel/.gconf/apps/gnome-terminal/profiles/Default/%gconf.xml
/lib/live/mount/rootfs/filesystem.squashfs/root/.gconf/apps/%gconf.xml
/lib/live/mount/rootfs/filesystem.squashfs/root/.gconf/apps/gnome-terminal/%gconf.xml
/lib/live/mount/rootfs/filesystem.squashfs/root/.gconf/apps/gnome-terminal/profiles/%gconf.xml
/lib/live/mount/rootfs/filesystem.squashfs/root/.gconf/apps/gnome-terminal/profiles/Default/%gconf.x






org.gnome.desktop.wm.keybindings maximize ['<Super>Up']


/org/onboard/keyboard/
/org/mate/desktop/accessibility/keyboard/
/org/mate/desktop/peripherals/keyboard/



/org/mate/settings-daemon/plugins/keyboard/
/org/mate/settings-daemon/plugins/a11y-keyboard/


/org/gnome/settings-daemon/plugins/keyboard/
/org/gnome/settings-daemon/peripherals/keyboard/
/org/gnome/settings-daemon/plugins/a11y-keyboard/
/org/gnome/desktop/peripherals/keyboard/
/org/gnome/desktop/a11y/keyboard/
/org/cinnamon/desktop/a11y/keyboard/



org.mate.peripherals-keyboard numlock-state 'on'
org.mate.peripherals-keyboard remember-numlock-state true




/org/mate/desktop/keybindings/


/org/mate/desktop/keybindings/custom10/
/org/mate/desktop/keybindings/custom10/action 'vlc'
/org/mate/desktop/keybindings/custom10/binding '<Alt>v'
/org/mate/desktop/keybindings/custom10/name 'VLC media player'

/org/mate/desktop/keybindings/custom11/
/org/mate/desktop/keybindings/custom11/action '/usr/bin/zuluMount-gui'
/org/mate/desktop/keybindings/custom11/binding '<Alt>z'
/org/mate/desktop/keybindings/custom11/name 'zuluMount'

/org/mate/desktop/keybindings/custom15/
/org/mate/desktop/keybindings/custom15/action 'firetools'
/org/mate/desktop/keybindings/custom15/binding 'F11'
/org/mate/desktop/keybindings/custom15/name 'Firejail Tools'

/org/mate/desktop/keybindings/custom23/
/org/mate/desktop/keybindings/custom23/action 'firejail-ui'
/org/mate/desktop/keybindings/custom23/binding '<Mod4>f'
/org/mate/desktop/keybindings/custom23/name 'Firejail Configuration Wizard'


/org/mate/desktop/keybindings/custom16/
/org/mate/desktop/keybindings/custom16/action '/usr/bin/seahorse'
/org/mate/desktop/keybindings/custom16/binding '<Alt>s'
/org/mate/desktop/keybindings/custom16/name 'Seahorse'

/org/mate/desktop/keybindings/custom17/
/org/mate/desktop/keybindings/custom17/action 'synaptic-pkexec'
/org/mate/desktop/keybindings/custom17/binding '<Primary><Shift>s'
/org/mate/desktop/keybindings/custom17/name 'Synaptic Package Manager'

/org/mate/desktop/keybindings/custom18/
/org/mate/desktop/keybindings/custom18/action 'gpa'
/org/mate/desktop/keybindings/custom18/binding "'<Alt>g'"
/org/mate/desktop/keybindings/custom18/name 'GPA'

/org/mate/desktop/keybindings/custom19/
/org/mate/desktop/keybindings/custom19/action 'pluma'
/org/mate/desktop/keybindings/custom19/binding 'F12'
/org/mate/desktop/keybindings/custom19/name 'Pluma'

/org/mate/desktop/keybindings/custom20/
/org/mate/desktop/keybindings/custom20/action 'lxterminal'
/org/mate/desktop/keybindings/custom20/binding 'F9'
/org/mate/desktop/keybindings/custom20/name 'lxterminal'

/org/mate/desktop/keybindings/custom21/
/org/mate/desktop/keybindings/custom21/action 'mate-screenshot --interactive'
/org/mate/desktop/keybindings/custom21/binding '<Shift>Print'
/org/mate/desktop/keybindings/custom21/name 'Take Screenshot'

/org/mate/desktop/keybindings/custom3/
/org/mate/desktop/keybindings/custom3/action 'geany'
/org/mate/desktop/keybindings/custom3/binding '<Alt>g'
/org/mate/desktop/keybindings/custom3/name 'geany'


/org/mate/desktop/keybindings/custom4/
/org/mate/desktop/keybindings/custom4/action 'audacious'
/org/mate/desktop/keybindings/custom4/binding '<Alt>a'
/org/mate/desktop/keybindings/custom4/name 'Audacious Qt Interface'

/org/mate/desktop/keybindings/custom5/
/org/mate/desktop/keybindings/custom5/action 'caja'
/org/mate/desktop/keybindings/custom5/binding 'F10'
/org/mate/desktop/keybindings/custom5/name 'Caja'

/org/mate/desktop/keybindings/custom6/
/org/mate/desktop/keybindings/custom6/binding 'disabled'
/org/mate/desktop/keybindings/custom6/name 'Claws Mail'

/org/mate/desktop/keybindings/custom7/
/org/mate/desktop/keybindings/custom7/action 'firefox-esr'
/org/mate/desktop/keybindings/custom7/binding '<Alt>f'
/org/mate/desktop/keybindings/custom7/name 'Firefox ESR Web Browser'


/org/mate/desktop/keybindings/custom0/
/org/mate/desktop/keybindings/custom0/action 'gnome-disks'
/org/mate/desktop/keybindings/custom0/binding '<Alt>d'
/org/mate/desktop/keybindings/custom0/name 'Disks'


/org/mate/desktop/keybindings/custom8/
/org/mate/desktop/keybindings/custom8/action '/usr/bin/gparted'
/org/mate/desktop/keybindings/custom8/binding '<Primary>g'
/org/mate/desktop/keybindings/custom8/name 'GParted Partition Editor'


/org/mate/desktop/keybindings/custom9/

/org/mate/desktop/keybindings/custom9/action 'mpv'
/org/mate/desktop/keybindings/custom9/binding 'F1'
/org/mate/desktop/keybindings/custom9/name 'mpv Media Player'








org.mate.sound event-sounds false























set_default ()
{
    gconftool-2 --config-source xml:readwrite:/etc/gconf/gconf.xml.defaults --type bool --set /apps/gksu/$1 $2
}

set_mandatory ()
{
    gconftool-2 --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gksu/$1 $2
}





	# Disable Printing in Gnome
	gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type bool \
              --set /desktop/gnome/lockdown/disable_printing true
	gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type bool \
              --set /desktop/gnome/lockdown/disable_print_setup true


	# Disable Quick User Switching in Gnome
	gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type bool \
              --set /desktop/gnome/lockdown/disable_user_switching true

	# Disable Gnome Power Settings
	gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type bool \
              --set /apps/gnome-power-manager/general/can_suspend false
	gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type bool \
              --set /apps/gnome-power-manager/general/can_hibernate false

gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type bool \
              --set /apps/nautilus/preferences/media_autorun_never true
	gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type bool \
              --set /apps/nautilus/preferences/media_automount_open false
	gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type bool \
              --set /apps/nautilus/preferences/media_automount false

	# NSA Recommendation: Disable Gnome Thumbnailers
	gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type bool \
              --set /desktop/gnome/thumbnailers/disable_all true


	# NIST 800-53 CCE-14023-6 (row 97)
	gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type bool \
              --set /apps/gnome-screensaver/lock_enabled true

	# NIST 800-53 CCE-14735-5 (row 98)
	gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type string \
              --set /apps/gnome-screensaver/mode blank-only

	# Disable Ctrl-Alt-Del in GNOME
	gconftool-2 --direct \
	      --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
	      --type string \
	      --set /apps/gnome_settings_daemon/keybindings/power ""
	      
	# Disable Clock Temperature
	gconftool-2 --direct \
	      --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
	      --type bool \
	      --set /apps/panel/applets/clock/prefs/show_temperature false

	# Disable Clock Weather
	gconftool-2 --direct \
	      --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
	      --type bool \
	      --set /apps/panel/applets/clock/prefs/show_weather false

	# Legal Banner on GDM
	gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type bool \
              --set /apps/gdm/simple-greeter/banner_message_enable true

	gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type string \
              --set /apps/gdm/simple-greeter/banner_message_text "$(cat /etc/issue)"

	# Disable User List on GDM
	gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type bool \
              --set /apps/gdm/simple-greeter/disable_user_list true

	# Disable Restart Buttons on GDM
	gconftool-2 --direct \
              --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
              --type bool \
              --set /apps/gdm/simple-greeter/disable_restart_buttons true


--all-entries
--recursive-list
--all-dirs
--dump

--install-schema-file=
--config-source=


gconftool-2 --type string --set /org/mate/desktop/keybindings/custom7/name 'zuluMount'
gconftool-2 --type string --set /org/mate/desktop/keybindings/custom7/action 'zuluMount-gui'
gconftool-2 --type string --set /org/mate/desktop/keybindings/custom7/binding '<Mod4>z'
gconftool-2 --type string --set 
gconftool-2 --type string --set 

gconftool-2 --type string --set 
gconftool-2 --type string --set 





/org/mate/desktop/keybindings/


/org/mate/desktop/keybindings/custom7/
/org/mate/desktop/keybindings/custom7/action 'zuluMount-gui'
/org/mate/desktop/keybindings/custom7/binding '<Mod4>z'
/org/mate/desktop/keybindings/custom7/name 'zuluMount'


/org/mate/desktop/keybindings/custom6/name 'gnome-disks'
/org/mate/desktop/keybindings/custom6/action 'gnome-disks'
/org/mate/desktop/keybindings/custom6/binding '<Mod4>d'


/org/mate/desktop/keybindings/custom9/
/org/mate/desktop/keybindings/custom9/name 'Pluma Text Editor {Firejail Sandboxed}'
/org/mate/desktop/keybindings/custom9/action 'firejail --profile=/etc/firejail/pluma.profile /usr/bin/pluma %U'
/org/mate/desktop/keybindings/custom9/binding '<Mod4>p'


/org/mate/desktop/keybindings/custom16/name 'Geany {Firejail Sandboxed}'
/org/mate/desktop/keybindings/custom16/action 'firejail --profile=/etc/firejail/geany.profile --net=none /usr/bin/geany'
/org/mate/desktop/keybindings/custom16/binding '<Mod4>g'


/org/mate/desktop/keybindings/custom10/name 'Audacious {Firejail Sandboxed}'
/org/mate/desktop/keybindings/custom10/action 'firejail --profile=/etc/firejail/audacious.profile --net=none /usr/bin/audacious %U'
/org/mate/desktop/keybindings/custom10/binding '<Mod4>a'


/org/mate/desktop/keybindings/custom4/name 'MPV Media Player {Firejail Sandboxed}'
/org/mate/desktop/keybindings/custom4/action 'firejail --profile=/etc/firejail/mpv.profile --net=none --private-tmp /usr/bin/mpv --player-operation-mode=pseudo-gui'
/org/mate/desktop/keybindings/custom4/binding '<Mod4>m'


/org/mate/desktop/keybindings/custom11/name 'VLC Media Player {Firejail Sandboxed}'
/org/mate/desktop/keybindings/custom11/action 'firejail --name=vlc --profile=/etc/firejail/vlc.profile --net=none /usr/bin/vlc'
/org/mate/desktop/keybindings/custom11/binding '<Mod4>v'


/org/mate/desktop/keybindings/custom12/name 'vokoscreen'
/org/mate/desktop/keybindings/custom12/action 'vokoscreen'
/org/mate/desktop/keybindings/custom12/binding '<Mod4>r'


/org/mate/desktop/keybindings/custom5/name 'screenshot'
/org/mate/desktop/keybindings/custom5/action 'mate-screenshot --interactive'
/org/mate/desktop/keybindings/custom5/binding 'Print'


/org/mate/desktop/keybindings/custom8/name 'displays'
/org/mate/desktop/keybindings/custom8/action 'mate-display-properties'
/org/mate/desktop/keybindings/custom8/binding '<Mod4>m'


/org/mate/desktop/keybindings/custom14/name 'Atril {Firejail Sandbox Profile}'
/org/mate/desktop/keybindings/custom14/action 'firejail --name=atril --profile=/etc/firejail/atril.profile --net=none /usr/bin/atril %U'
/org/mate/desktop/keybindings/custom14/binding '<Mod4>a'


/org/mate/desktop/keybindings/custom15/name 'Eye of MATE Image Viewer {Firejail Sandboxed}'
/org/mate/desktop/keybindings/custom15/action 'firejail --profile=/etc/firejail/eom.profile /usr/bin/eom %U'
/org/mate/desktop/keybindings/custom15/binding '<Mod4>i'


/org/mate/desktop/keybindings/custom19/name 'Seahorse'
/org/mate/desktop/keybindings/custom19/action '/usr/bin/seahorse'
/org/mate/desktop/keybindings/custom19/binding '<Mod4>s'


/org/mate/desktop/keybindings/custom18/name 'GSmartControl'
/org/mate/desktop/keybindings/custom18/action 'su-to-root -X -c gsmartcontrol'
/org/mate/desktop/keybindings/custom18/binding '<Mod4>h'








/org/mate/marco/window-keybindings/


org.mate.Marco.window-keybindings maximize '<Primary>Up'
org.mate.Marco.window-keybindings minimize '<Primary>Down'

org.mate.Marco.window-keybindings move-to-side-e '<Control><Alt>KP_Right'
org.mate.Marco.window-keybindings move-to-side-n '<Control><Alt>KP_Up'
org.mate.Marco.window-keybindings move-to-side-s '<Control><Alt>KP_Down'
org.mate.Marco.window-keybindings move-to-side-w '<Control><Alt>KP_Left'

org.mate.Marco.window-keybindings tile-to-corner-ne '<Primary>KP_9'
org.mate.Marco.window-keybindings tile-to-corner-nw '<Primary>KP_7'
org.mate.Marco.window-keybindings tile-to-corner-se '<Primary>KP_3'
org.mate.Marco.window-keybindings tile-to-corner-sw '<Primary>KP_1'
org.mate.Marco.window-keybindings tile-to-side-e '<Primary>Right'
org.mate.Marco.window-keybindings tile-to-side-w '<Primary>Left'

org.mate.Marco.window-keybindings toggle-on-all-workspaces '<Primary>Home'




org.mate.Marco.workspace-names name-1 'Main'
org.mate.Marco.workspace-names name-2 'Terminal'
org.mate.Marco.workspace-names name-3 'Pr0n'
org.mate.Marco.workspace-names name-4 'Hardware'



org.mate.mate-menu.plugins.recent num-recent-docs 25
org.mate.mate-menu.plugins.system_management show-control-center true
org.mate.mate-menu.plugins.system_management show-lock-screen true




gsettings get 
gsettings set 

gsettings list-schemas
list-relocatable-schemas

xdg-desktop-menu forceupdate


list-children             List children of a schema
  list-recursively          List keys and values, recursively
  range                     Queries the range of a key
  describe                  Queries the description of a key



gsettings set org.mate.SettingsDaemon.plugins.keybindings
gsettings set org.mate.Marco.global-keybindings
gsettings set org.mate.Marco.keybinding-commands
gsettings set org.mate.mate-menu
gsettings set org.mate.accessibility-keyboard






