#!/bin/sh
## youtube-dl-master-README.sh


$ youtube-dl --get-filename -o '%(title)s.%(ext)s' BaW_jenozKc
youtube-dl test video ''_ä↭𝕐.mp4    # All kinds of weird characters

$ youtube-dl --get-filename -o '%(title)s.%(ext)s' BaW_jenozKc --restrict-filenames
youtube-dl_test_video_.mp4          # A simple file name

# Download YouTube playlist videos in separate directory indexed by video order in a playlist
$ youtube-dl -o '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/playlist?list=PLwiyx1dc3P2JR9N8gQaQN_BCvlSlap7re

# Download all playlists of YouTube channel/user keeping each playlist in separate directory:
$ youtube-dl -o '%(uploader)s/%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s' https://www.youtube.com/user/TheLinuxFoundation/playlists

# Download Udemy course keeping each chapter in separate directory under MyVideos directory in your home
$ youtube-dl -u user -p password -o '~/MyVideos/%(playlist)s/%(chapter_number)s - %(chapter)s/%(title)s.%(ext)s' https://www.udemy.com/java-tutorial/

# Download entire series season keeping each series and each season in separate directory under C:/MyVideos
$ youtube-dl -o "C:/MyVideos/%(series)s/%(season_number)s - %(season)s/%(episode_number)s - %(episode)s.%(ext)s" https://videomore.ru/kino_v_detalayah/5_sezon/367617

# Stream the video being downloaded to stdout
$ youtube-dl -o - BaW_jenozKc



# Download best mp4 format available or any other best if no mp4 available
$ youtube-dl -f 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best'

# Download best format available but not better that 480p
$ youtube-dl -f 'bestvideo[height<=480]+bestaudio/best[height<=480]'

# Download best video only format but no bigger than 50 MB
$ youtube-dl -f 'best[filesize<50M]'

# Download best format available via direct link over HTTP/HTTPS protocol
$ youtube-dl -f '(bestvideo+bestaudio/best)[protocol^=http]'

# Download the best video format and the best audio format without merging them
$ youtube-dl -f 'bestvideo,bestaudio' -o '%(title)s.f%(format_id)s.%(ext)s'


youtube-dl -f '(bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best)[protocol^=http]'




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







