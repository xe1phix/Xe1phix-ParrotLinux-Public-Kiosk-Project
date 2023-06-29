#!/bin/sh
## ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ##
alias ytdlaudio="youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(title)s.%(ext)s' $1"
alias ytdlaplaylist="youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' $1"
## ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ##
alias ytdlvideo="youtube-dl --verbose --continue --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' -o '%(title)s.%(ext)s' $1"
alias ytdlvplaylist="youtube-dl --verbose --continue --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline --print-traffic -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' $1"
## ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ##
## 
## ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ##
## Download Single Video,Using OpenVPN SOCKS5 Proxy Then Convert To MP3:
alias ytdlopenvpnaudio="youtube-dl --verbose --force-ipv4 --proxy socks5://10.8.0.1:1080 --continue --extract-audio -f 'bestaudio/best' --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(title)s.%(ext)s' $1"
## ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ##
## Download Single Video, Wireguard SOCKS5 Proxy Then Convert To MP3:
alias ytdlwireguardaudio="youtube-dl --verbose --force-ipv4 --proxy socks5://10.64.0.1:1080 --continue --extract-audio -f 'bestaudio/best' --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(title)s.%(ext)s' $1"
## ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ##
## Download Entire Playlist Using OpenVPN SOCKS5 Proxy Then Convert To MP3:
alias ytdlaplaylistopenvpn="youtube-dl --verbose --force-ipv4 --proxy socks5://10.8.0.1:1080 --continue --extract-audio -f 'bestaudio/best' --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' $1"
## ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ##
## Download Entire Playlist Using Wireguard SOCKS5 Proxy Then Convert To MP3:
alias ytdlaplaylistwireguard= "youtube-dl --verbose --force-ipv4 --proxy socks5://10.64.0.1:1080 --continue --extract-audio -f 'bestaudio/best' --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' $1"
## ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ##
## Download Best Quality MP4 - Using Wireguard SOCKS5 Proxy:
alias ytdlwireguardvideo="youtube-dl --verbose --continue --force-ipv4 --proxy socks5://10.64.0.1 --ffmpeg-location /usr/bin/ffmpeg --newline -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' -o '%(title)s.%(ext)s' $1"
## ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ##


