## grep aliases
alias grep="grep --color=always"
alias ngrep="grep -n"

alias egrep="egrep --color=auto"

alias fgrep="fgrep --color=auto"

## tmux
alias tmux="tmux attach || tmux new"

## axel
alias axel="axel -a"

## screen
alias screen="screen -xRR"

## nmap scripts
alias nse="grc -s ls /usr/share/nmap/scripts | grep"

## Checksums
alias sha1="openssl sha1"
alias md5="openssl md5"

## python web server
alias pyweb="python -m SimpleHTTPServer 8000"

## ping count 5
alias check="grc -s ping -c 5"

## cd lab
alias lab="cd ~/lab" 

## cd lab
alias bbt="cd ~/BB-Tools" 

## list file pref
alias lh="grc -s ls -lisAd .[^.]*" 

## List open ports
alias ports="grc -s netstat -tulanp"

## Get header
alias header="curl -I"

## Get external IP address
alias ipx="curl -s http://ipinfo.io/ip"

## DNS - External IP #1
alias dns1="dig +short @resolver1.opendns.com myip.opendns.com"

## DNS - External IP #2
alias dns2="dig +short @208.67.222.222 myip.opendns.com"

### DNS - Check ("#.abc" is Okay)
alias dns3="dig +short @208.67.220.220 which.opendns.com txt"

## Directory navigation aliases
alias ..="cd .."
alias ...="cd ../.."
alias ....="cd ../../.."
alias .....="cd ../../../.."

## Extract file, example. "ex package.tar.bz2"
ex() {
  if [[ -f $1 ]]; then
    case $1 in
      *.tar.bz2)   tar xjf $1  ;;
      *.tar.gz)  tar xzf $1  ;;
      *.bz2)     bunzip2 $1  ;;
      *.rar)     rar x $1  ;;
      *.gz)    gunzip $1   ;;
      *.tar)     tar xf $1   ;;
      *.tbz2)    tar xjf $1  ;;
      *.tgz)     tar xzf $1  ;;
      *.zip)     unzip $1  ;;
      *.Z)     uncompress $1  ;;
      *.7z)    7z x $1   ;;
      *)       echo $1 cannot be extracted ;;
    esac
  else
    echo $1 is not a valid file
  fi
}

## strings
alias strings="strings -a"

## history
alias hg="history | grep"

## Add more aliases
alias upd="sudo apt update"
alias upg="sudo apt upgrade"
alias ins="sudo apt install"
alias rem="sudo apt purge"
alias fix="sudo apt install -f"

## aircrack-ng
alias aircrack-ng="aircrack-ng -z"

## airodump-ng 
alias airodump-ng="airodump-ng --manufacturer --wps --uptime"

## metasploit
alias msfc="systemctl start postgresql; msfdb start; msfconsole -q \"$@\""
alias msfconsole="systemctl start postgresql; msfdb start; msfconsole \"$@\""

## openvas
alias openvas="openvas-stop; openvas-start; sleep 3s; xdg-open https://127.0.0.1:9392/ >/dev/null 2>&1"

## ssh
alias ssh-start="systemctl restart ssh"
alias ssh-stop="systemctl stop ssh"

## www
alias wwwroot="cd /var/www/html/"
#alias www="cd /var/www/html/"

## ftp
alias ftproot="cd /var/ftp/"

## tftp
alias tftproot="cd /var/tftp/"

## smb
alias sambaroot="cd /var/samba/"
#alias smbroot="cd /var/samba/"

## vmware
alias vmroot="cd /mnt/hgfs/"

## edb
alias edb="cd /usr/share/exploitdb/platforms/"
alias edbroot="cd /usr/share/exploitdb/platforms/"

## wordlist
alias wordlist="cd /usr/share/wordlists/"
alias wordls="cd /usr/share/wordlists/"

alias msfvenom-list-all='cat ~/.msf4/msfvenom/all'
alias msfvenom-list-nops='cat ~/.msf4/msfvenom/nops'
alias msfvenom-list-payloads='cat ~/.msf4/msfvenom/payloads'
alias msfvenom-list-encoders='cat ~/.msf4/msfvenom/encoders'
alias msfvenom-list-formats='cat ~/.msf4/msfvenom/formats'
alias msfvenom-list-generate='_msfvenom-list-generate'
function _msfvenom-list-generate {
  mkdir -p ~/.msf4/msfvenom/
  msfvenom --list > ~/.msf4/msfvenom/all
  msfvenom --list nops > ~/.msf4/msfvenom/nops
  msfvenom --list payloads > ~/.msf4/msfvenom/payloads
  msfvenom --list encoders > ~/.msf4/msfvenom/encoders
  msfvenom --help-formats 2> ~/.msf4/msfvenom/formats
}
