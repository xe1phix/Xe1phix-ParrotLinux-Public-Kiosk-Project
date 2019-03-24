#!/bin/sh
##-=========================================================-##
##   [+] Xe1phix-YouTube-DL-OneCheatsheetToRuleThemAll.sh
##-=========================================================-##


## Download Single Video, Formatting It With The Best Quality Audio + Video (Output As: MP4)
youtube-dl --verbose --continue --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' -o '%(title)s.%(ext)s' 


## Download Entire Playlist, Formatting The Videos With Best Quality Audio + Video (Output As: MP4)
youtube-dl --verbose --continue --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline --print-traffic -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' 


## Download Single Video, Then Convert To MP3:
youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(title)s.%(ext)s' 


## Download Entire Playlist, Then Convert To MP3:
youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' 


