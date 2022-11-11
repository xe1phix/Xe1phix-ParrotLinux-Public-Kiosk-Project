############################
# Download the Analysis VM #
############################
https://s3.amazonaws.com/infosecaddictsvirtualmachines/InfoSecAddictsVM.zip
user: infosecaddicts
pass: infosecaddicts
 
 
 
- Log in to your Ubuntu system with the username 'infosecaddicts' and the password 'infosecaddicts'.
 
 
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
 
wget https://s3.amazonaws.com/infosecaddictsfiles/hn_forensics.vmem
 
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
