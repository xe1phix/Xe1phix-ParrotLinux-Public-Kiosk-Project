#!/bin/bash

# Tested on Parrot OS

#Temp
# echo "\x1b[32m ---> [   ]\\x1b[0m\n";


echo "Zumkato Bug Bounty Tool And Space Setup"
echo "________________________________"
echo "________________________________"
echo "________________________________"
echo "________________________________"
printf "\x1b[32m ---> [ Creating Folder ]\\x1b[0m\n";
mkdir -pv ~/BB-Tools/Targets

cd ~/BB-Tools


#install go
if [[ -z "$GOPATH" ]];then
echo "It looks like go is not installed, would you like to install it now"
PS3="Please select an option : "
choices=("yes" "no")
select choice in "${choices[@]}"; do
        case $choice in
                yes)

                                        echo "-----------------------"
                                        printf "\x1b[32m ---> [ Installing Golang  ]\\x1b[0m\n";
                                        wget https://go.dev/dl/go1.17.6.linux-amd64.tar.gz
                                        tar -xvf go1.17.6.linux-amd64.tar.gz
                                        mv go /usr/local
                                        export GOROOT=/usr/local/go
                                        export GOPATH=$HOME/go
                                        export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
                                        echo 'export GOROOT=/usr/local/go' >> ~/.bash_profile
                                        echo 'export GOPATH=$HOME/go'   >> ~/.bash_profile
                                        echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bash_profile
                                        source ~/.bash_profile
                                        sleep 1
                                        break
                                        ;;
                                no)
                                        echo "Please install go and rerun this script"
                                        echo "Aborting installation ~/BB-Tools."
                                        exit 1
                                        ;;
        esac
done
fi



printf "\x1b[32m ---> [ Installing APT packages  ]\\x1b[0m\n";
apt update
apt upgrade -y
apt install -y python-dnspython
apt install -y xsltproc
apt install -y libcurl4-openssl-dev
apt install -y libssl-dev
apt install -y jq
apt install -y ruby-full
apt install -y libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev
apt install -y build-essential libssl-dev libffi-dev python-dev
apt install -y python-setuptools
apt install -y libldns-dev
apt install -y python3-pip
apt install -y python-pip
apt install -y python-dnspython
apt install -y git
apt install -y rename
apt install -y xargs
apt install -y libldns-dev
apt install -y awscli
apt install -y amass
apt install -y npm chromium parallel
snap install  xmind

printf "\x1b[32m ---> [ installing bash_profile aliases from recon_profile"
git clone https://github.com/nahamsec/recon_profile.git
cd recon_profile
cat bash_profile >> ~/.bash_profile
source ~/.bash_profile
cd ~/BB-Tools

printf "\x1b[32m ---> [ Install SSL Testing Tools  ]\\x1b[0m\n";
git clone https://github.com/hahwul/a2sv.git
cd a2sv
pip3 install -r requirements.txt
cd ~/BB-Tools

printf "\x1b[32m ---> [ Downloading Arjun ]\\x1b[0m\n";
git clone -q https://github.com/s0md3v/Arjun.git

printf "\x1b[32m ---> [ Installing XSStrike ]\\x1b[0m\n";
git clone https://github.com/s0md3v/XSStrike.git
cd XXSStrike
pip3 install -r requirements.txt
cd ~/BB-Tools

printf "\x1b[32m ---> [ Installing Corsy ]\\x1b[0m\n";
git clone  https://github.com/s0md3v/Corsy.git
cd Corsy
pip3 install -r requirements.txt
cd ~/BB-Tools

printf "\x1b[32m ---> [ Installing SourceLeakHacker ]\\x1b[0m\n";
https://github.com/WangYihang/SourceLeakHacker.git
pip3 install -r requirements.txt
cd ~/BB-Tools


printf "\x1b[32m ---> [ Installing subscraper  ]\\x1b[0m\n";
git clone https://github.com/Cillian-Collins/subscraper.git
cd subscraper
pip3 install -r requirements.txt
cd ~/BB-Tools

printf "\x1b[32m ---> [  Installing git-search ]\\x1b[0m\n";
git clone https://github.com/gwen001/github-search.git
cd github-search
pip3 install -r requirements.txt
pip3 install -r requirements2.txt
pip3 install -r requirements3.txt
cd ~/BB-Tools

printf "\x1b[32m ---> [  Installing Subfinder ]\\x1b[0m\n";
git clone https://github.com/projectdiscovery/subfinder.git
cd subfinder/cmd/subfinder
go build .
mv subfinder /usr/local/bin/
cd ~/BB-Tools

printf "\x1b[32m ---> [ Downloading nMap_Merger  ]\\x1b[0m\n";
git clone https://github.com/CBHue/nMap_Merger.git

printf "\x1b[32m ---> [ Installing Nuclei  ]\\x1b[0m\n";
git clone https://github.com/projectdiscovery/nuclei.git
cd nuclei/v2/cmd/nuclei/
go build .
mv nuclei /usr/local/bin/
git clone https://github.com/projectdiscovery/nuclei-templates.git
nuclei -update-templates
cd ~/BB-Tools

printf "\x1b[32m ---> [ Installing Osmedeus  ]\\x1b[0m\n";
git clone https://github.com/j3ssie/Osmedeus
cd Osmedeus
bash install.sh
cd ~/BB-Tools

printf "\x1b[32m ---> [  Installing IntruderPayloads ]\\x1b[0m\n";
git clone https://github.com/1N3/IntruderPayloads.git
cd IntruderPayloads
bash install.sh
cd ~/BB-Tools

printf "\x1b[32m ---> [  Downloading xss payload  ]\\x1b[0m\n";
git clone https://github.com/payloadbox/xss-payload-list.git

printf "\x1b[32m ---> [ Installing S3Scanner  ]\\x1b[0m\n";
git clone https://github.com/sa7mon/S3Scanner.git
cd S3Scanner
pip install -r requirements.txt
cd ~/BB-Tools

printf "\x1b[32m ---> [  Installing Domained ]\\x1b[0m\n";
git clone https://github.com/TypeError/domained.git
cd domained
python3 domained.py --install
pip3 install -r ./ext/requirements.txt
cd ~/BB-Tools


printf "\x1b[32m ---> [ Installing VHostScan ]\\x1b[0m\n";
git clone https://github.com/codingo/VHostScan.git
cd VHostScan
python3 setup.py install
cd ~/BB-Tools


printf "\x1b[32m ---> [ Downloading assessment-mindset  ]\\x1b[0m\n";
git clone https://github.com/dsopas/assessment-mindset.git


printf "\x1b[32m ---> [ Installing Sudomy  ]\\x1b[0m\n";
git clone https://github.com/Screetsec/Sudomy.git
cd Sudomy
pip3 install -requirements.txt
npm i -g wappalyzer wscat
cd ~/BB-Tools

printf "\x1b[32m ---> [  Installing Interlace ]\\x1b[0m\n";
git clone https://github.com/codingo/Interlace.git
cd Interlace
python3 setup.py install
cd ~/BB-Tools

printf "\x1b[32m ---> [ Installing SubDomainizer  ]\\x1b[0m\n";
git clone https://github.com/nsonaniya2010/SubDomainizer.git
cd SubDomainizer
pip3 install -r requirements.txt
cd ~/BB-Tools

printf "\x1b[32m ---> [ Installing ParamSpider  ]\\x1b[0m\n";
git clone https://github.com/devanshbatham/ParamSpider.git
cd ParamSpider
pip3 install -r requirements.txt
cd ~/BB-Tools

printf "\x1b[32m ---> [ Downloading Firewall Bypass for DNS  ]\\x1b[0m\n";
git clone https://github.com/vincentcox/bypass-firewalls-by-DNS-history.git

printf "\x1b[32m ---> [ Downloading LFISuite  ]\\x1b[0m\n";
git clone https://github.com/D35m0nd142/LFISuite.git

printf "\x1b[32m ---> [ Installing NoSQLMap  ]\\x1b[0m\n";
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap
python setup.py install
cd ~/BB-Tools

printf "\x1b[32m ---> [  Downloading default login checker ]\\x1b[0m\n";
git clone https://github.com/InfosecMatter/default-http-login-hunter.git

printf "\x1b[32m ---> [  Downloading OpenRedireX  ]\\x1b[0m\n";
 git clone https://github.com/devanshbatham/OpenRedireX

printf "\x1b[32m ---> [ Installing swiftnessx  ]\\x1b[0m\n";
git clone https://github.com/ehrishirajsharma/swiftnessx.git
cd swiftnessx
yarn
yarn dev
cd ~/BB-Tools

printf "\x1b[32m ---> [ Downloading Sn1per  ]\\x1b[0m\n";
git clone https://github.com/1N3/Sn1per.git

printf "\x1b[32m ---> [ Downloading SSRFTest  ]\\x1b[0m\n";
git clone https://github.com/daeken/SSRFTest.git

printf "\x1b[32m ---> [ Installing gitGraber  ]\\x1b[0m\n";
git clone https://github.com/hisxo/gitGraber.git
cd gitGraber
pip3 install -r requirements.txt
cd ~/BB-Tools

printf "\x1b[32m ---> [ Downloading virtual host discovery   ]\\x1b[0m\n";
git clone https://github.com/jobertabma/virtual-host-discovery.git

printf "\x1b[32m ---> [ Download s3 bucketeers  ]\\x1b[0m\n";
git clone https://github.com/tomdev/teh_s3_bucketeers.git

printf "\x1b[32m ---> [ Installing Knock  ]\\x1b[0m\n";
git clone https://github.com/guelfoweb/knock.git
cd knock
python setup.py install
cd ~/BB-Tools

printf "\x1b[32m ---> [ Installing DNS-Discovery  ]\\x1b[0m\n";
git clone https://github.com/m0nad/DNS-Discovery.git
cd DNS-Discovery
make
cd ~/BB-Tools

printf "\x1b[32m ---> [ Installing tplmap  ]\\x1b[0m\n";
git clone https://github.com/epinna/tplmap.git
cd tplmap
pip install -r requirements.txt
cd ~/BB-Tools

printf "\x1b[32m ---> [ Installing reconftw  ]\\x1b[0m\n";
git clone https://github.com/six2dez/reconftw
cd reconftw
chmod +x *.sh
cd ~/BB-Tools

printf "\x1b[32m ---> [ Installing 4-ZERO-3  ]\\x1b[0m\n";
git clone https://github.com/Dheerajmadhukar/4-ZERO-3.git
chmod +x *.sh
cd ~/BB-Tools

printf "\x1b[32m ---> [ Installing reconftw  ]\\x1b[0m\n";
git clone https://github.com/samhaxr/recox
cd recox
chmod +x recox.sh
cd ~/BB-Tools


printf "\x1b[32m ---> [ Installing Subcert  ]\\x1b[0m\n";
git clone https://github.com/A3h1nt/Subcert.git
pip3 install -r requirements.txt
mv subcert /opt/
alias subcert="python3 /opt/subcert/subcert.py"

printf "\x1b[32m ---> [ Installing sql-injection-payloads  ]\\x1b[0m\n";
https://github.com/payloadbox/sql-injection-payload-list.git

# GO Installs
printf "\x1b[32m ---> [ Installing GetJS ]\\x1b[0m\n";
go get github.com/003random/getJS

printf "\x1b[32m ---> [ Installing subjack ]\\x1b[0m\n";
go get github.com/haccer/subjack

printf "\x1b[32m ---> [ Installing httprobe ]\\x1b[0m\n";
go get -u github.com/tomnomnom/httprobe

printf "\x1b[32m ---> [ Installing unfurl ]\\x1b[0m\n";
go get -u github.com/tomnomnom/unfurl

printf "\x1b[32m ---> [ Installing waybackurls  ]\\x1b[0m\n";
go get github.com/tomnomnom/waybackurls

printf "\x1b[32m ---> [ Installing FFUF  ]\\x1b[0m\n";
go get github.com/ffuf/ffuf

printf "\x1b[32m ---> [ Installing aquatone  ]\\x1b[0m\n";
go get github.com/michenriksen/aquatone

printf "\x1b[32m ---> [ Installing metabigor  ]\\x1b[0m\n";
go get -u github.com/j3ssie/metabigor

printf "\x1b[32m ---> [ Installing hakrawler  ]\\x1b[0m\n";
go get github.com/hakluke/hakrawler

printf "\x1b[32m ---> [ Installing assetfinder  ]\\x1b[0m\n";
go get -u github.com/tomnomnom/assetfinder

printf "\x1b[32m ---> [ Installing shuffledns  ]\\x1b[0m\n";
GO111MODULE=on go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns

printf "\x1b[32m ---> [ Installing GetAllurls ]\\x1b[0m\n";
GO111MODULE=on go get -u -v github.com/lc/gau

printf "\x1b[32m ---> [ Installing Gron  ]\\x1b[0m\n";
go get -u github.com/tomnomnom/gron

printf "\x1b[32m ---> [ Installing GF  ]\\x1b[0m\n";
go get -u github.com/tomnomnom/gf
source ~/path/to/gf-completion.zsh

printf "\x1b[32m ---> [ Installing dontgo403  ]\\x1b[0m\n";
git clone https://github.com/devploit/dontgo403; cd dontgo403; go get; go build

printf "\x1b[32m ---> [ Installing http2smugl  ]\\x1b[0m\n";
go get github.com/neex/http2smugl

printf "\x1b[32m ---> [ Installing second-order  ]\\x1b[0m\n";
go install -v github.com/mhmdiaa/second-order@latest

printf "\x1b[32m ---> [ Installing interactsh-client  ]\\x1b[0m\n";
GO111MODULE=on go get -v github.com/projectdiscovery/interactsh/cmd/interactsh-client



wget https://github.com/takito1812/log4j-detect/raw/main/log4j-detect.py


GO111MODULE=on go get -u -v github.com/lc/gau
#pip Installs


printf "\x1b[32m ---> [ Installing pip tools ]\\x1b[0m\n";
pip3 install httpie
pip3 install dnsgen
pip3 install whatweb
pip3 install pwncat

echo "done"

#Installing Rust and cargo

printf "\x1b[32m ---> [ Installing Rust and cargo  ]\\x1b[0m\n";
curl https://sh.rustup.rs -sSf | sh
echo "checking if good install  ~/BB-Tools."
source ~/.bash_profile
echo "checking if good install  ~/BB-Tools."
cargo install rustscan
export CARGOPATH=$HOME/.cargo
PATH=$CARGOPATH/bin:$PATH
source ~/.bash_profile

git clone https://github.com/Edu4rdSHL/findomain.git
cd findomain
cargo build --release
cp target/release/findomain /usr/bin/

cd ~/BB-Tools
git clone https://github.com/0xsha/GoLinkFinder.git
cd GoLinkFinder
go build GoLinkfinder.go

#pushd /opt/shellconv-git/ >/dev/null
#git pull -q
#popd >/dev/null
#--- Add to path
#file=/usr/local/bin/shellconv-git
#cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
#cd /opt/shellconv-git/ && python shellconv.py "\$@"
#EOF
#chmod +x "${file}"



echo -e "\n\n\n\n\n\n\n\n\n\n\nDone! All tools are set up in ~/BB-Tools"
cd ~/BB-Tools

ls-l

echo "One last time: don't forget to set up AWS credentials in ~/.aws/!"
