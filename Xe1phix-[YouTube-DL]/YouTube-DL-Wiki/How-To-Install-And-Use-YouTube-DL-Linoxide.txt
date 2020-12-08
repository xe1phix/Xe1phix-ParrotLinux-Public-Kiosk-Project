How to Install and Use YouTube-DL on Ubuntu 18.04
July 26, 2018LINUX HOWTO, OPEN SOURCE TOOLSUpdated July 26, 2018

This guide will take you through how to install and use Install YouTube-DL on Ubuntu 18.04. YouTube-DL is a command line tool written in Python to help users download videos from YouTube, Dailymotion, Yahoo, Facebook, Flickr,  PressTV and many other sites. YouTube-DL is a cross-platform piece of software, it runs on Windows, Linux/Unix, and macOS.

YouTube-DL support download from many sites in different formats, both as a video and audio files. By default, youtube-dl will pick the highest quality but you can obtain low quality if you have a slow internet connection by passing some options.

Other good features of youtube-dl include:

    Resuming interrupted downloads
    Extracting mp3 from video files
    Downloading all video files from a playlist
    Download only the videos uploaded in the last x days
    Set  Maximum download rate
    Embed subtitle into the video while downloading

How to install youtube-dl on Ubuntu

There are three ways to install youtube-dl on Ubuntu 18.04 system. We will consider installation of youtube-dl from all the three methods:
Install youtube-dl from apt

The first and easy method is installing youtube-dl from apt repository. For this, you just need to run the command:

$ sudo apt-get install youtube-dl

Install youtube-dl using pip

youtube-dl package can also be installed using pip. First, install packagepython-pip.

$ sudo apt-get install python-pip

Once pip is present on the system, use it to install youtube-dl :

$ sudo pip install youtube-dl

Install youtube-dl from binary

Youtube-dl is also distributed as a binary package which you can download and install it.

sudo wget https://yt-dl.org/latest/youtube-dl -O /usr/local/bin/youtube-dl
sudo chmod a+x /usr/local/bin/youtube-dl
hash -r

Any of the three methods should work fine for you.
Update YouTube-DL

You can always update youtube-dl to the latest release using the command below:

$ sudo youtube-dl -U

How to Use youtube-dl

Once you have installed youtube-dl , see below examples of how to download Videos and extract audio with youtube-dl.
Download highest quality video

To download the highest quality of a video from a URL, use the command:

$ youtube-dl example.com/watch?v=id

Check available video formats

YouTube-DL supports a multitude of formats, e.g  Mp4, mkv, webm, FLV e.t.c. To list available video codes, use -F option. E.g

$ youtube-dl -F https://youtu.be/FLV1z9BWvyc
18 mp4 640x360 medium , avc1.42001E, [email protected] 96k, 26.70MiB
43 webm 640x360 medium , vp8.0, [email protected], 30.47MiB
22 mp4 1280x720 hd720 , avc1.64001F, [email protected] (best)

Take note of the format number - 18,43,22. This is used when downloading the video.
Download Specific video format

After getting a list of formats available, download specific format using -f format-number. E.g

$ youtube-dl -f 22 https://youtu.be/FLV1z9BWvyc

This will download format/codec1280x720 hd720.
Download Audio

You can also download audio using youtube-dl  like below:

youtube-dl --extract-audio --audio-format mp3 example.com/watch?v=id

This will extract audio from the video and save it to disk.
Download a video playlist

Youtube-dl saves all videos on a playlist by default. Just copy playlist URL and pass it to youtube-dl command line tool.

$ youtube-dl example.com/watch?v=id&list=listid

You can also start from a specified number.

$ youtube-dl --playlist-start 5 example.com/watch?v=id&list=listid

Force resume of partially downloaded files

To force resume of partially downloaded files without overriding completed, use -cwi options:

$ youtube-dl -cwi video-url

Use a proxy server to download files

$ youtube-dl --proxy 127.0.0.1:3128

Download and embed subtitles to a video

Use the option --write-auto-sub to download Video subtitles if available.

$ youtube-dl --write-auto-sub <other-options> <url>
