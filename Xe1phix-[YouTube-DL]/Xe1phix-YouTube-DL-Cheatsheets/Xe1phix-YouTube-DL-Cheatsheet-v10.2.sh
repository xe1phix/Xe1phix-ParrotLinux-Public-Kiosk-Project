#!/bin/sh
## youtube-dl-master-README.sh





alias yt2mp3='youtube-dl -l --extract-audio --audio-format=mp3 -w -c'




youtube-dl --get-filename -o '%(title)s.%(ext)s' BaW_jenozKc
youtube-dl test video ''_ä↭𝕐.mp4    # All kinds of weird characters

youtube-dl --get-filename -o '%(title)s.%(ext)s' BaW_jenozKc --restrict-filenames
youtube-dl_test_video_.mp4          # A simple file name

# Download YouTube playlist videos in separate directory indexed by video order in a playlist
youtube-dl -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PLwiyx1dc3P2JR9N8gQaQN_BCvlSlap7re

# Download all playlists of YouTube channel/user keeping each playlist in separate directory:
youtube-dl -o '%(uploader)s/%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/user/TheLinuxFoundation/playlists

# Download Udemy course keeping each chapter in separate directory under MyVideos directory in your home
youtube-dl -u user -p password -o '~/MyVideos/%(playlist)s/%(chapter_number)s - %(chapter)s/%(title)s.%(ext)s' https://www.udemy.com/java-tutorial/

# Download entire series season keeping each series and each season in separate directory under C:/MyVideos
youtube-dl -o "C:/MyVideos/%(series)s/%(season_number)s - %(season)s/%(episode_number)s - %(episode)s.%(ext)s" https://videomore.ru/kino_v_detalayah/5_sezon/367617

# Stream the video being downloaded to stdout
youtube-dl -o - BaW_jenozKc



# Download best mp4 format available or any other best if no mp4 available
youtube-dl -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best'

# Download best format available but not better that 480p
youtube-dl -f 'bestvideo[height<=480]+bestaudio/best[height<=480]'

# Download best video only format but no bigger than 50 MB
youtube-dl -f 'best[filesize<50M]'

# Download best format available via direct link over HTTP/HTTPS protocol
youtube-dl -f '(bestvideo+bestaudio/best)[protocol^=http]'

# Download the best video format and the best audio format without merging them
youtube-dl -f 'bestvideo,bestaudio' -o '%(title)s.f%(format_id)s.%(ext)s'


youtube-dl -f '(bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best)[protocol^=http]'


# Play music from youtube without download
wget -q -O - `youtube-dl -b -g $url`| ffmpeg -i - -f mp3 -vn -acodec libmp3lame -| mpg123  -


# Create an animated gif from a Youtube video
url=http://www.youtube.com/watch?v=V5bYDhZBFLA; youtube-dl -b $url; mplayer $(ls ${url##*=}*| tail -n1) -ss 00:57 -endpos 10 -vo gif89a:fps=5:output=output.gif -vf scale=400:300 -nosound





# Download only the videos uploaded in the last 6 months
$ youtube-dl --dateafter now-6months

# Download only the videos uploaded on January 1, 1970
$ youtube-dl --date 19700101

$ # Download only the videos uploaded in the 200x decade
$ youtube-dl --dateafter 20000101 --datebefore 20091231




## streaming to vlc can be achieved with:
youtube-dl -o - "https://www.youtube.com/watch?v=BaW_jenozKcj" | vlc -

## download only new videos from a playlist?
youtube-dl --download-archive archive.txt "https://www.youtube.com/playlist?list=PLwiyx1dc3P2JR9N8gQaQN_BCvlSlap7re"



# Download single entry
youtube-dl -i --extract-audio --audio-format mp3 --audio-quality 0 YT_URL

# Download playlist
youtube-dl -ict --yes-playlist --extract-audio --audio-format mp3 --audio-quality 0 https://www.youtube.com/playlist?list=UUCvVpbYRgYjMN7mG7qQN0Pg

# Download playlist, --download-archive downloaded.txt add successfully downloaded files into downloaded.txt
youtube-dl --download-archive downloaded.txt --no-overwrites -ict --yes-playlist --extract-audio --audio-format mp3 --audio-quality 0 --socket-timeout 5 https://www.youtube.com/playlist?list=UUCvVpbYRgYjMN7mG7qQN0Pg

# Retry until success, no -i option
while ! youtube-dl --download-archive downloaded.txt --no-overwrites -ct --yes-playlist --extract-audio --audio-format mp3 --audio-quality 0 --socket-timeout 5 <YT_PlayList_URL>; do echo DISCONNECTED; sleep 5; done






mp3 () {
	youtube-dl --ignore-errors -f bestaudio --extract-audio --audio-format mp3 --audio-quality 0 -o '~/Music/youtube/%(title)s.%(ext)s' "$1"
}


mp3p () {
	youtube-dl --ignore-errors -f bestaudio --extract-audio --audio-format mp3 --audio-quality 0 -o '~/Music/youtube/%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' "$1"
}


dlv () {
	youtube-dl --ignore-errors -o '~/Videos/youtube/%(title)s.%(ext)s' "$1"
}

dlp () {
	youtube-dl --ignore-errors -o '~/Videos/youtube/%(playlist)s/%(title)s.%(ext)s' "$1"
}






youtube-dl -f bestaudio --audio-quality 0 --audio-format mp3 https://www.youtube.com/watch?v=3zy1SNH-VqE


youtube-dl -x -f bestaudio --audio-quality 0 --audio-format mp3 



list the available formats with youtube-dl -F:

youtube-dl -F https://www.youtube.com/watch?v=3zy1SNH-VqE
youtube-dl --list-formats


youtube-dl -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/mp4' 

--format bestvideo+bestaudio[ext=m4a]/bestvideo+bestaudio/best 




youtube-dl -x --audio-format mp3 



converting to .mp3:

youtube-dl -f bestaudio --ffmpeg-location /path/to/ffmpeg -o '/path/output/%(title)s.%(ext)s' -x --audio-quality 4 --audio-format mp3 --add-metadata --embed-thumbnail -i URLGOESHERE


## bestvideo+bestaudio, saves both streams into an .mkv container 
youtube-dl -f bestvideo+bestaudio --merge-output-format mkv --ffmpeg-location /path/to/ffmpeg -o '/path/output/%(title)s.%(ext)s' --embed-thumbnail -i URLGOESHERE


youtube-dl -a youtube_links.txt



youtube-dl -citk –format mp4 –yes-playlist https://www.youtube.com/watch?v=7Vy8970q0Xc&list=PLwJ2VKmefmxpUJEGB1ff6yUZ5Zd7Gegn2

youtube-dl -i -f mp4 --yes-playlist 'https://www.youtube.com/watch?v=7Vy8970q0Xc&list=PLwJ2VKmefmxpUJEGB1ff6yUZ5Zd7Gegn2'



youtube-dl --extract-audio --audio-format mp3 -o "%(title)s.%(ext)s" <url to playlist>

youtube-dl -cit --extract-audio --audio-format mp3 https://www.youtube.com/playlist?list=PLttJ4RON7sleuL8wDpxbKHbSJ7BH4vvCk



youtube-dl -cit <playlist_url>



--external-downloader curl
--external-downloader wget
--external-downloader 

--list-thumbnails
--write-all-thumbnails

--user-agent

--add-metadata
--embed-thumbnail
--metadata-from-title "%(artist)s - %(title)s"
--xattrs



## Download all playlists of YouTube channel/user 
## keeping each playlist in separate directory:
youtube-dl -o '%(uploader)s/%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/user/TheLinuxFoundation/playlists
              
## up to 720p videos (or videos where the height is not known) 
## with a bitrate of at least 500 KBit/s.
-f "[height <=? 720][tbr>500]"


## if you are not interested in getting videos with a resolution higher than 1080p
-f bestvideo[height<=?1080]+bestaudio/best

--geo-bypass

youtube-dl -o - "https://www.youtube.com/watch?v=BaW_jenozKcj" | vlc -

--cookies /path/to/cookies/file.txt

download the best mp4 and webm formats with a height lower than 480 you can use 
-f '(mp4,webm)[height<480]'

youtube-dl --dump-user-agent
youtube-dl --user-agent
youtube-dl --user-agent "Mozilla/5.0 (Windows NT 10.0; ARM; Lumia 950 Dual SIM) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393"

youtube-dl --print-traffic
youtube-dl --newline
youtube-dl --verbose

--continue


youtube-dl --list-formats


youtube-dl --recode-video mp4

youtube-dl --prefer-ffmpeg
youtube-dl --ffmpeg-location /usr/bin/ffmpeg
youtube-dl --ffmpeg-location /usr/bin/avconv


youtube-dl --verbose --extract-audio --audio-format mp3 --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline 

youtube-dl --verbose --extract-audio --audio-format mp3 --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline https://www.youtube.com/watch?v=zrQdHebBmW4


youtube-dl --verbose --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PLhzl7jzJnJGw3NS-bwF63KnSNmO1dUemh

youtube-dl --verbose --continue --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' -o '%(title)s.%(ext)s' 

youtube-dl --verbose --force-ipv4 --extract-audio --audio-quality 4 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' 


youtube-dl --verbose --force-ipv4 --extract-audio --audio-quality 4 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PLElrASo3VHBxeA1NQp0Bz2EwmmMtE9JPD


### Psybient Greatest All Time Mix (+ Animated 16Bit Sci-Fi Visuals)-eqzxBHSKVsQ
youtube-dl --verbose --extract-audio --audio-format mp3 --audio-quality 4 --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline https://www.youtube.com/watch?v=eqzxBHSKVsQ


youtube-dl --verbose --continue --extract-audio --audio-format mp3 --audio-quality 4 --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline 



## Mikko Hyppönen keynotes
youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-quality 4 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PL3Gxs8cWjMi0ggYh1A3_EDN7rsqpCt4nr


## Bruce Schneier
youtube-dl --verbose --force-ipv4 --extract-audio --audio-quality 4 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PLElrASo3VHBxeA1NQp0Bz2EwmmMtE9JPD

youtube-dl --verbose --force-ipv4 --download-archive schneier.txt --no-overwrites --extract-audio --audio-quality 4 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PLElrASo3VHBxeA1NQp0Bz2EwmmMtE9JPD
youtube-dl --verbose --force-ipv4 --download-archive schneier.txt --no-overwrites --continue --extract-audio --audio-quality 4 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PLElrASo3VHBxeA1NQp0Bz2EwmmMtE9JPD

youtube-dl --verbose --force-ipv4 --playlist-reverse --no-overwrites --continue --extract-audio --audio-quality 4 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PLElrASo3VHBxeA1NQp0Bz2EwmmMtE9JPD

youtube-dl --verbose --get-url https://www.youtube.com/playlist?list=PLElrASo3VHBxeA1NQp0Bz2EwmmMtE9JPD

## DEF CON 22 - Zoz - Don't Fuck It Up! 
youtube-dl --verbose --continue --extract-audio --audio-format mp3 --audio-quality 4 --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline https://www.youtube.com/watch?v=J1q4Ir2J8P8


youtube-dl --verbose --continue --extract-audio --audio-format mp3 --audio-quality 4 --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline https://www.youtube.com/watch?v=UeZjWdg_Qn8


https://www.youtube.com/playlist?list=PL_oIgFxFuQEmk4stb9M93sn9tW0n9eQhw

## download only new videos from a playlist
youtube-dl --download-archive archive.txt "https://www.youtube.com/playlist?list=PLwiyx1dc3P2JR9N8gQaQN_BCvlSlap7re"




## The Next HOPE (2010) - Keynote Address - Wikileaks.m4v 
youtube-dl --verbose --continue --extract-audio --audio-format mp3 --audio-quality 4 --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline https://www.youtube.com/watch?v=aRVDIohWPVM

## 30c3: To Protect And Infect, Part 2 
https://www.youtube.com/watch?v=b0w36GAyZIA&index=23&list=PLpSATnX81Tw54OMTFttEWtFc5kogolNuL&t=0s

## 
## 30C3 To Protect And Infect - The militarization of the Internet
youtube-dl --verbose --continue --extract-audio --audio-format mp3 --audio-quality 4 --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline https://www.youtube.com/watch?v=Y1aU3uw1QnA

## Jacob Appelbaum leaks more NSA documents @ 30c3 
https://www.youtube.com/watch?v=DQ0OhDHK0Ds&index=42&list=PLpSATnX81Tw54OMTFttEWtFc5kogolNuL&t=0s

## Jacob Appelbaum - A Technical Action Plan - Project Bullrun
youtube-dl --verbose --continue --extract-audio --audio-format mp3 --audio-quality 4 --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline https://www.youtube.com/watch?v=tddXVCqSftw

## What is to be done - Reflections on Free Software Usage
youtube-dl --verbose --continue --extract-audio --audio-format mp3 --audio-quality 4 --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline https://www.youtube.com/watch?v=emoXPiXcp3A


## Invited Talk - Jacob Appelbaum
youtube-dl --verbose --continue --extract-audio --audio-format mp3 --audio-quality 4 --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline https://www.youtube.com/watch?v=n9Xw3z-8oP4


## re:publica 2012 - Appelbaum & Kleiner - Resisting the Surveillance State and its network effects



## DOCUMENTARY: Edward Snowden - Terminal F (2015) 


## LoganCIJ16: Future of OS 
youtube-dl --verbose --continue --extract-audio --audio-format mp3 --audio-quality 4 --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline https://www.youtube.com/watch?v=Nol8kKoB-co

## To Protect And Infect Part 2 (Jacob Applebaum )
youtube-dl --verbose --continue --extract-audio --audio-format mp3 --audio-quality 4 --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline https://www.youtube.com/watch?v=vtQ7LNeC8Cs






## list the available formats:
youtube-dl -F https://www.youtube.com/watch?v=3zy1SNH-VqE
youtube-dl --list-formats https://www.youtube.com/watch?v=3zy1SNH-VqE


## Download Single Video, Formatting It With The Best Quality Audio + Video (Output As: MP4)
youtube-dl --verbose --continue --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' -o '%(title)s.%(ext)s' 


## Download Entire Playlist, Formatting The Videos With Best Quality Audio + Video (Output As: MP4)
youtube-dl --verbose --continue --yes-playlist --no-overwrites --ignore-errors --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline --print-traffic -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' 


## Download Single Video, Then Convert To MP3:
youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(title)s.%(ext)s' 


## Download Entire Playlist, Then Convert To MP3:
youtube-dl --verbose --force-ipv4 --yes-playlist --continue --no-overwrites --ignore-errors --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' 


## Download all playlists of YouTube channel/user keeping each playlist in separate directory:
youtube-dl -o '%(uploader)s/%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' 


## stream directly to VLC
youtube-dl -o - "https://www.youtube.com/watch?v=BaW_jenozKcj" | vlc -


## Save downloaded files to ~/Videos folder
youtube-dl --verbose --force-ipv4 --continue --ffmpeg-location /usr/bin/ffmpeg --newline -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' -o ~/Videos/%(title)s.%(ext)s 


## Download only videos not listed in the archive file.
youtube-dl --verbose --force-ipv4 --continue --no-overwrites --ignore-errors --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline --download-archive $Archive.txt -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' 


## Batch download Urls found in $file.txt
youtube-dl --verbose --force-ipv4 --continue --no-overwrites --ignore-errors --batch-file $file.txt --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(title)s.%(ext)s' 


## Force bypass geographic restriction 
## By provided two-letter ISO 3166-2 country code
## https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes
youtube-dl --verbose --force-ipv4 --continue --no-overwrites --ignore-errors --geo-bypass-country $CA --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' 






## Flyleaf-acoustic
https://www.youtube.com/watch?v=fKuzaPV-af4&list=PL250902E39D4C26E4&index=2&t=0s



https://www.youtube.com/playlist?list=PLMBKj1HtMyoSwnviGv5WKXjGxRMSDrUHa

https://www.youtube.com/playlist?list=PLk1H6jjyiPIRLpM2qqkAfUh9h1PVbnogr


https://www.youtube.com/playlist?list=PLRZEf4_VCtFgeRh3XFG5zPZK_-fxNyEvx

https://www.youtube.com/watch?v=fud-Lz76MHg
https://www.youtube.com/watch?v=fud-Lz76MHg


## Evanescence Fallen Full Album 
youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PL6ogdCG3tAWh0wI2fu43S1EwfeZSecBZb
## The Open Door
youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PL5x4G_lRgApubIHLenYGhC9ltzpYfvJMn



## Seether
youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PL7MZNkK_CwYxvLOzoPYRDkj_D2cnFdk77
youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PLRloLUfqwtbnWjGY1wCyNwUj5VxbRChET
youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PLwJGCOTGehITo8Vh-8umL0bnnAAWnU5u4
youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PLVyROVsjyTAsvsBxRthzW_S8rUNebJucL
youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PL7MZNkK_CwYxUH-WxjICqhP_FOsn5skhd

## Savatage - 'Hall Of The Mountain King' (Full Album)
youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(title)s.%(ext)s' https://youtube.com/watch?v=mKNIHaBCkcw


https://youtube.com/channel/UCxt8Iutjk2eU1-wzixETTog



https://youtube.com/watch?v=DJyJ485sC5w



youtube-dl --verbose --force-ipv4 --continue --ignore-errors --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PL62490033DD23FF3C


youtube-dl --verbose --force-ipv4 --continue --ignore-errors --playlist-end 13 --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PLA88A8A520275DB84



youtube-dl --verbose --force-ipv4 --yes-playlist --continue --no-overwrites --ignore-errors --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PLJNbijG2M7Ox5T8gwIxKpEP81Vt2IGpJ_


youtube-dl --verbose --force-ipv4 --yes-playlist --continue --no-overwrites --ignore-errors --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PLzM_6mmjF1FNCbPHw7L6yVZYa__mnKQi9



youtube-dl --verbose --continue --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' -o '%(title)s.%(ext)s' https://www.youtube.com/watch?v=W47f2cke4Vg

youtube-dl --verbose --continue --force-ipv4 --ffmpeg-location /usr/bin/ffmpeg --newline -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' -o '%(title)s.%(ext)s' https://www.youtube.com/watch?v=A1PJHn-tYrc


youtube-dl --verbose --force-ipv4 --continue --extract-audio --audio-quality 3 --audio-format mp3 --ffmpeg-location /usr/bin/ffmpeg --newline -o '%(title)s.%(ext)s' https://www.youtube.com/watch?v=ABuNwLP-z9o




