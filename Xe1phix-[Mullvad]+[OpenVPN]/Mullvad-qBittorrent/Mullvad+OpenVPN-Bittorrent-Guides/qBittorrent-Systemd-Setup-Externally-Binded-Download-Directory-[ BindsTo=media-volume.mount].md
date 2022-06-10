### (Optional) Service Dependencies ###

Let's say that you configured qbittorrent-nox to download files to a directory that is in another drive, for example, mounted on '/media/volume'. It's important that you edit the service created above and add some systemd dependencies to prevent qbittorrent from writing files on a directory that it should not, in case your drive fails to mount or is accidentally unmounted.

After you added the mount point to the `/etc/fstab`, it should have a line like this:
```
UUID=c987355d-0ddf-4dc7-bbbc-bab8989d0690 /media/volume  ext4     defaults,nofail 0       0
```
The 'nofail' option prevents the system from stopping the boot process in case the drive can't mount on startup.

You should edit `/etc/systemd/system/qbittorrent.service` to add 'local-fs.target' to the line 'After=network.target' and add the line 'BindsTo=media-volume.mount' to bind the qbittorrent service to the mount point that you want it to write the files. Your service file should look like this: 
```
[Unit]
Description=qBittorrent Daemon Service
After=network.target local-fs.target
BindsTo=media-volume.mount

[Service]
User=qbtuser
ExecStart=/usr/bin/qbittorrent-nox
ExecStop=/usr/bin/killall -w qbittorrent-nox

[Install]
WantedBy=multi-user.target
```

The 'media-volume.mount' is a systemd unit created dynamically at boot, based on the entries found on `/etc/fstab`
and is used by systemd to mount and manage the status of the respective drive. [Systemd.mount reference](http://man7.org/linux/man-pages/man5/systemd.mount.5.html)
It follows a simple logic: if your drive is mounted on '/media/volume', the unit name will be 'media-volume.mount', if it's on '/mnt/disk', the unit will be 'mnt-disk.mount'.

This way, if the drive can't mount on boot or if the drive is unmounted after qbittorrent started, it will not allow it to start or force it to stop, preventing from writing when the drive is not ready or present.
