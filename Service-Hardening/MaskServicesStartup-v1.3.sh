


sudo deluser --remove-all-files bluetooth && sudo systemctl mask bluetooth.service && sudo update-rc.d bluetooth remove && sudo deluser --remove-all-files postgresql && sudo systemctl mask postgresql.service && sudo deluser --remove-all-files samba-ad-dc && sudo systemctl mask samba-ad-dc.service && sudo deluser --remove-all-files snmpd && sudo systemctl mask snmpd.service && sudo update-rc.d snmpd remove && sudo deluser --remove-all-files apache2 && sudo systemctl mask apache2.service && sudo update-rc.d apache2 remove && sudo deluser --remove-all-files smbd && sudo systemctl mask smbd.service && sudo update-rc.d smbd remove && sudo deluser --remove-all-files mysql && sudo systemctl mask mysql.service && sudo update-rc.d mysql remove && sudo deluser --remove-all-files sambashare && sudo systemctl mask sambashare.service && sudo update-rc.d sambashare remove 


deluser --remove-all-files bluetooth && systemctl mask bluetooth.service && update-rc.d bluetooth remove && deluser --remove-all-files postgresql && systemctl mask postgresql.service && deluser --remove-all-files samba-ad-dc && systemctl mask samba-ad-dc.service && deluser --remove-all-files snmpd && systemctl mask snmpd.service && update-rc.d snmpd remove && deluser --remove-all-files apache2 && systemctl mask apache2.service && update-rc.d apache2 remove && deluser --remove-all-files smbd && systemctl mask smbd.service && update-rc.d smbd remove && deluser --remove-all-files mysql && systemctl mask mysql.service && update-rc.d mysql remove
deluser --remove-all-files sambashare && systemctl mask sambashare.service && update-rc.d sambashare remove 




