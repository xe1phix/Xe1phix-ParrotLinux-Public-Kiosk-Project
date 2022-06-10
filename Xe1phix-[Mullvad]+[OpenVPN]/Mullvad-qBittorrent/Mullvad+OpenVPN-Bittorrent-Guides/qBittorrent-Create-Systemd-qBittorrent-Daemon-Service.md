### Create Service ###
First, create a file:
`/etc/systemd/system/qbittorrent.service`
```
[Unit]
Description=qBittorrent Daemon Service
After=network.target

[Service]
User=qbtuser
ExecStart=/usr/bin/qbittorrent-nox
ExecStop=/usr/bin/killall -w qbittorrent-nox

[Install]
WantedBy=multi-user.target
```

Normally after editing services we'd issue a reload command but since it will also invoke qbittorrent before we initialized the configuration, we'll give it a skip for now. If you ever make changes to the services file, update systemctl with:
```
$ sudo systemctl daemon-reload
```

