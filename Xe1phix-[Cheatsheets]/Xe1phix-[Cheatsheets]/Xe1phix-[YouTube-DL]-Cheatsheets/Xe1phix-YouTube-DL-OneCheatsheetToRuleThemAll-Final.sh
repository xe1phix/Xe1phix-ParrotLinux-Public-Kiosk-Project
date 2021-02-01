#!/bin/sh
##-=========================================================-##
##   [+] Xe1phix-YouTube-DL-OneCheatsheetToRuleThemAll.sh
##-=========================================================-##


## Download Single Video, Formatting It With The Best Quality Audio + Video (Output As: MP4)
youtube-dl --verbose --continue --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' -o '%(title)s.%(ext)s' 
youtube-dl --verbose --continue --limit-rate 250k --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' -o '%(title)s.%(ext)s' 

youtube-dl --verbose --continue --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline --format 'bestvideo[ext=mp4][height<=?720]+bestaudio/best' -o '%(title)s.%(ext)s' 

## Download Entire Playlist, Formatting The Videos With Best Quality Audio + Video (Output As: MP4)
youtube-dl --verbose --continue --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline --print-traffic -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' 


## Download Single Video, Then Convert To MP3:
youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(title)s.%(ext)s' 
youtube-dl --verbose --force-ipv4 --continue --format 'bestaudio/best' --extract-audio --audio-quality 0 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(title)s.%(ext)s' 
youtube-dl --verbose --force-ipv4 --continue --limit-rate 250k --format 'bestaudio/best' --extract-audio --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(title)s.%(ext)s' 
youtube-dl --verbose --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36" --force-ipv4 --continue --format 'bestaudio/best' --extract-audio --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(title)s.%(ext)s' 

## Download Entire Playlist, Then Convert To MP3:
youtube-dl --verbose --force-ipv4 --continue -f 'bestaudio/best' --extract-audio --audio-quality 2 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' 
youtube-dl --verbose --force-ipv4 --continue --limit-rate 250k -f 'bestaudio/best' --extract-audio --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' 

