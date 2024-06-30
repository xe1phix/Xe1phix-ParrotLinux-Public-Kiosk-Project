echo "STARTING QBITTORRENT"
exec sudo -u ${RUN_AS} /usr/bin/qbittorrent-nox --webui-port=8082 &


echo "Acquire::http {No-Cache=True;};" > /etc/apt/apt.conf.d/no-cache
echo "force-unsafe-io" > /etc/dpkg/dpkg.cfg.d/02apt-speedup



VOLUME /root/.local/share/data/qBittorrent
VOLUME /root/.config/qBittorrent

sed -i '/allowed_users/c\allowed_users=anybody' 


sudo chown $UNAME:$UGROUP "$folder" || { echo -e "${RED}Chown on $folder failed.$ENDCOLOR"; exit 1; }
    sudo chmod -R 775 "$folder" || { echo -e "${RED}Chmod on $folder failed.$ENDCOLOR"; exit 1; }










dconf read KEY

dconf list DIR

dconf write KEY VALUE

dconf reset [-f] PATH

dconf compile OUTPUT KEYFILEDIR

dconf update

dconf watch PATH

dconf dump DIR

dconf load DIR 
