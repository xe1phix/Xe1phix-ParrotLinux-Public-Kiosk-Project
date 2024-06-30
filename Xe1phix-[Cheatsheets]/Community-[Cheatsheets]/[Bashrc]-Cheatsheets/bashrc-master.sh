# prompt

# CentOS global bashrc
if [ -f /etc/bashrc ]
then
  source /etc/bashrc
fi

charmap=$( locale charmap )
if [[ ${TERM} =~ ^xterm.* ]]
then
  TITLEBAR='\[\033]0;@\h\007\]'
else
  TITLEBAR=""
fi
if [ "${charmap}" = "UTF-8" ]
then
  PS1="${TITLEBAR}\$? \$([ \$? -eq 0 ] && echo \"\[\033[01;32m\]\342\234\223\[\033[00m\]\" || echo \"\[\033[01;31m\]\342\234\227\[\033[00m\]\") @\h:\w\\$ "
else
  PS1="${TITLEBAR}@\h:\W\\$ "
fi

# https://www.gnupg.org/documentation/manuals/gnupg/Invoking-GPG_002dAGENT.html
export GPG_TTY=$(tty)
# GnuPG 2.1
if [ -S ~/.gnupg/S.gpg-agent.ssh ]
then
  export SSH_AUTH_SOCK=~/.gnupg/S.gpg-agent.ssh
# old method
elif [ -f "${HOME}/.gnupg/gpg-agent-info-$(hostname)" ]
then
  . "${HOME}/.gnupg/gpg-agent-info-$(hostname)"
  export GPG_AGENT_INFO
  export SSH_AUTH_SOCK
fi

# https://www.gnupg.org/documentation/manuals/gnupg/Common-Problems.html
if [ -n "${SSH_CONNECTION}" ]
then
  gpg-connect-agent updatestartuptty /bye
else
  # only use this locally
  alias gvim='gvim -p --servername gvim --remote-tab-silent'
fi

LS_OPTIONS='--color=auto'
eval "`/usr/bin/dircolors -b`"
alias ls='ls ${LS_OPTIONS}'
# http://vim.wikia.com/wiki/Enable_servername_capability_in_vim/xterm
# http://vim.wikia.com/wiki/Launch_files_in_new_tabs_under_Unix
export TAR_OPTIONS="--numeric-owner"

threads=$(cat /proc/cpuinfo | grep vendor_id | wc -l)
export	BUNDLEJOBS=${threads}
export	MAKEFLAGS="-j ${threads}"
unset	threads

if /usr/bin/gpg2 --version | head -1 | grep -q "^gpg.*2\.1.[0-9]\+$"
then
  alias gpg='/usr/bin/gpg2'
fi

shopt -s checkwinsize

HISTCONTROL="ignoreboth"
export HISTIGNORE="bitcoin-cli walletpassphrase *"

# set session timeout for root
if [ "${USER}" = "root" ]
then
  TMOUT=1200
fi

LESSHISTFILE="/dev/null"
LESSSECURE=1
# slackware
if [ -f /usr/bin/lesspipe.sh ]
then
  LESSOPEN="|/usr/bin/lesspipe.sh %s"
# debian
elif [ -f /usr/bin/lesspipe ]
then
  LESSOPEN="|/usr/bin/lesspipe %s"
fi
export LESSOPEN
export LESS="--RAW-CONTROL-CHARS"
export PAGER="/usr/bin/less -i"
export MANPAGER="/usr/bin/less -is"
export EDITOR="/usr/bin/vim"
#export GREP_OPTIONS="--color=auto"
if [ -n "${GOROOT}" ]
then
  export GOPATH="${HOME}/go"
  export PATH="${PATH}:${GOPATH}/bin"
fi

# colored GCC warnings and errors
export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'

if [ -z "${BASH_COMPLETION_COMPAT_DIR}" -a -f /usr/share/bash-completion/bash_completion ]
then
  . /usr/share/bash-completion/bash_completion
fi

# jump between words with ctrl-(left|right)
# https://stackoverflow.com/questions/5029118/bash-ctrl-to-move-cursor-between-words-strings
bind '"\e[1;5C":forward-word'
bind '"\e[1;5D":backward-word'
