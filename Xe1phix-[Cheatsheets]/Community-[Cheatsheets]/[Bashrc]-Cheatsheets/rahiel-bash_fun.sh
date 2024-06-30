# -*- mode: shell-script; -*-

# colors
alias dir='dir --color=auto'
alias vdir='vdir --color=auto'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'

# verbose
alias rm='rm -Iv'
alias cp='cp -iv'
alias mv='mv -iv'
alias mkdir='mkdir -p -v'
alias rmdir='rmdir -p -v'

# ls
alias ls='ls --color=always --human-readable --classify --time-style=long-iso'
alias l='ls -l'
alias la='ls -A'
alias ll='ls -lA'

# less options
export LESS='--ignore-case --status-column --LONG-PROMPT --RAW-CONTROL-CHARS --HILITE-UNREAD --window=-4 --shift 1'

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'
alias tg='telegram-send "$([ $? = 0 ] && echo "" || echo "error: ") $(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*tg$//'\'')"'

# human
alias du="du -h"
alias df="df -h"
alias free="free -h"

alias sudo='sudo ' # pass alias to sudo
alias open='xdg-open'
alias watch='watch -n1'

# python
alias py='python3'
alias ipy='ipython3 -i'
alias mypy='mypy --check-untyped-defs --ignore-missing-imports'
alias pylab='ipython3 -i --pylab auto'
alias pyd='pydoc3'

# haskell
alias 'ghci'="stack exec ghci --"
alias 'ghc'="stack exec ghc --"

# LaTeX
alias latexmk='latexmk -interaction=nonstopmode -pvc -pdf -pdflatex="pdflatex -shell-escape %O %S"'
alias latexmk_err='latexmk -pvc -pdf -pdflatex="pdflatex -shell-escape %O %S"'
alias pdflatex='pdflatex -shell-escape'

alias binds="bind -P | grep 'can be'"
alias dd='dd status=progress'
alias e='emacsclient -nw'
alias em='emacsclient -c -n'
alias eq='emacs -Q'
alias emacsd='emacs --daemon'
alias j='z'
alias keys='xmodmap ~/.config/xmodmaprc'
alias netrestart="sudo systemctl restart network-manager.service"
alias nocaps='setxkbmap -option ctrl:nocaps'
alias pls='sudo $(fc -nl -1)'
alias rg='rg -S'
alias untar='tar xvf'
alias webserver='python3 -m http.server'
alias wget='wget -c'
alias xdaliclock='xdaliclock -24 -builtin3 -fullscreen'

# updates
alias debup='sudo apt update && sudo apt full-upgrade && sudo apt --purge autoremove'
alias fzf_update='cd ~/.local/fzf && git pull && ./install --key-bindings --completion --no-update-rc && cd -'
alias z_update='cd ~/.local/z && git pull && cd -'
alias npm_update='npm -g update'
alias pip_upgrade='pip3 install --upgrade -r ~/Sync/dotfiles/requirements.txt'

debin () { dpkg --get-selections | grep "$1"; }
calc () { bc -l <<< "$@"; }
ffind () { find . -iname "*$@*"; }
pyprofile () { python3 -m cProfile -s "tottime" "$@" | less; }
runp () { ps aux | grep "$@"; }

rot13() {
    if [ $# = 0 ] ; then
        tr "[a-m][n-z][A-M][N-Z]" "[n-z][a-m][N-Z][A-M]"
    else
        tr "[a-m][n-z][A-M][N-Z]" "[n-z][a-m][N-Z][A-M]" < "$1"
    fi
}

# "repeat" command.  Like: repeat 10 echo foo
repeat () {
           local count="$1" i;
           shift;
           for i in $(_seq 1 "$count");
           do
               eval "$@";
           done
       }

# Subfunction needed by `repeat'.
_seq () {
    local lower upper output;
    lower=$1 upper=$2;

    if [ $lower -ge $upper ]; then return; fi
    while [ $lower -lt $upper ];
    do
        echo -n "$lower "
        lower=$(($lower + 1))
    done
    echo "$lower"
}

