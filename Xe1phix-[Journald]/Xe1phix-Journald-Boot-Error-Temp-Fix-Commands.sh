mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
setfacl -Rnm g:wheel:rx,d:g:wheel:rx,g:adm:rx,d:g:adm:rx /var/log/journal/

journalctl --setup-keys
journalctl --sync
journalctl --rotate

journalctl --flush
