

gnome-terminal -x avconv -i "$I" -acodec mp3 "${I%.*}"."$extension"
ffmpeg -i "$I" -vn -c:a copy "${I%.*}"."$extension"
ffmpeg -f concat -i mylist -c copy combined."$extension"


ffmpeg-normalize -u -v -m -l $norm $I

ffmpeg -f concat -i mylist -c copy combined."$extension"


# Find videos and conver
find . -iname "*.mp4" -mtime -900 -print0 | xargs -n1 -I{} ffmpeg -i {} -c:v libx264 -c:a copy ~/Downloads/GOPRO/{}
find . -iname "*.mp4" -mtime -900 -print0 | xargs -0 -n1 -I{} ffmpeg -i {} -c:v libx264 -c:a copy ~/Downloads/GOPRO/{}

# Testing automatic encoding
ffmpeg /Volumes/Untitled/DCIM/100GOPRO/GOPR0514.MP4 ~/Downloads/GOPRO0514.webm
ffmpeg -i /Volumes/Untitled/DCIM/100GOPRO/GOPR0514.MP4 ~/Downloads/GOPRO0514.webm
ffmpeg -i /Volumes/Untitled/DCIM/100GOPRO/GOPR0514.MP4 ~/Downloads/GOPRO0514.webm


ffmpeg -i /Volumes/Untitled/DCIM/100GOPRO/GOPR0513.MP4 -c:v vp9 -c:a libvorbis ~/Downloads/GOPR0513.mkv
ffmpeg -i /Volumes/Untitled/DCIM/100GOPRO/GOPR0513.MP4 -c:v copy -c:a libvorbis ~/Downloads/GOPR0513-02.mkv
ffmpeg -i /Volumes/Untitled/DCIM/100GOPRO/GOPR0514.MP4 -c:v libx264 -c:a copy ~/Downloads/GOPR0514-05.mp4

ffmpeg -i /Volumes/Untitled/DCIM/100GOPRO/GOPR0514.MP4 -c:v libx264 -c:a copy -ss 00:00:00 -t 10 ~/Downloads/GOPR0513-02.mkv
ffmpeg -i /Volumes/Untitled/DCIM/100GOPRO/GOPR0514.MP4 -c:v libx264 -c:a copy -ss 00:00:00 -t 5 ~/Downloads/GOPR0514-02.mkv
ffmpeg -i /Volumes/Untitled/DCIM/100GOPRO/GOPR0514.MP4 -c:v libx264 -c:a copy -ss 00:00:00 -t 5 ~/Downloads/GOPR0514-04.mp4

# Cut videos
ffmpeg -i GOPR0430.MP4 -c:v copy -c:a copy -ss 00:00:00 -t 30 GOPR0430-01.MP4
ffmpeg -i GOPR0430.MP4 -c:v copy -c:a copy -ss 00:30:00 -t 30 GOPR0430-02.MP4
ffmpeg -i GOPR0430.MP4 -c:v copy -c:a copy -ss 00:00:30 GOPR0430-02.MP4
ffmpeg -i GOPR0432.MP4 -c:v copy -c:a copy -ss 00:00:00 -t 52 GOPR0432-01.MP4
ffmpeg -i GOPR0432.MP4 -c:v copy -c:a copy -ss 00:00:52  GOPR0432-02.MP4

# Testing diferent formats
ffmpeg -i video.mp4 -vc vp8 -ac vorbis -o video.webm
ffmpeg -i video.mp4 -vc vp8 -ac vorbis video.webm
ffmpeg -i video.mp4 -vc libvpx -ac libvorbis video.webm
ffmpeg -i video.mp4 -v:c libvpx -a:c libvorbis -o video.webm
ffmpeg -i video.mp4 -v:c libvpx -a:c libvorbis video.webm
ffmpeg -i video.mp4 -v:c vp8 -a:c libvorbis video.webm
ffmpeg -i video.mp4 -c:v libvpx -c:a libvorbis video.webm
ffmpeg -i video.mp4 -c copy -c:v libx264 video-libx264.mp4

# Set language of first audio
ffmpeg -i video.webm -c copy -c:a copy -metadata:s:a:0 language=eng video.webm
ffmpeg -y -i video.mp4 -c copy -c:a copy -metadata:s:a:0 language=eng video.mp4

# Info about available codecs for encode
ffmpeg -codecs | grep '..E.'  # Available codecs for encode
ffmpeg -codecs | grep '.EV.'  # Available codecs for encode video
ffmpeg -codecs | grep '.EA.'  # Available codecs for encode audio

# Search info for specific codec
ffmpeg -codecs | grep divx
ffmpeg -codecs | grep xvide
ffmpeg -codecs | grep xvid
ffmpeg -codecs | grep div
ffmpeg -codecs | grep mmpeg
ffmpeg -codecs | grep mpeg
ffmpeg -codecs | grep mp3
ffmpeg -codecs | grep mpeg
ffmpeg -codecs | grep 265
ffmpeg -codecs | grep aac
ffmpeg -codecs | grep ac
ffmpeg -codecs | grep webm
ffmpeg -codecs | grep wmv
ffmpeg -codecs | grep m4a
ffmpeg -codecs | grep theora
ffmpeg -codecs | grep aac
ffmpeg -codecs | grep vp9
ffmpeg -codecs | grep vp
ffmpeg -codecs | grep x26

# Some transformations over video
ffmpeg -i FSMs.mp4 -c:v libx264 -c:a copy FSMs-libx264.mp4  # x264
ffmpeg -i FSMs.mp4 -c:v libvpx -c:a libvorbis FSMs-libvpx-libvorbis.mp4
ffmpeg -i FSMs.mp4 -c:v libvpx -c:a libvorbis FSMs-libvpx-libvorbis.webm  # VP8-Vorbis
ffmpeg -i FSMs.mp4 -c:v libxvid -c:a libmp3lame FSMs-libxvid-libmp3lame.avi  # XVID
ffmpeg -i FSMs.mp4 -c:v libx265 -c:a copy FSMs-libx265.mp4  # x265

# Extract audio
ffmpeg -i FSMs.mp4 -vn -c:a libmp3lame FSMs.mp3  # MP3 (Audio only)
ffmpeg -i FSMs.mp4 -vn -c:a aac FSMs.aac  # AAC (Audio only)
ffmpeg -i FSMs.mp4 -vn -c:a libvorbis FSMs.ogg  # Vorbis (Audio only)
ffmpeg -i FSMs.mp4 -vn -c:a copy FSMs-copy.aac  # AAC (Direct copy) (Audio only)
ffmpeg -i FSMs.mp4 -vn -c:a libopus FSMs.opus  # Opus (Audio only)

# DVD, VCD, SVCD
ffmpeg -i FSMs.opus FSMs.mp4 -target ntsc-dvd FSMs-dvd.mp4  # DVD
ffmpeg -i FSMs.mp4 -target ntsc-dvd FSMs-dvd.mp4  # DVD
ffmpeg -i FSMs.mp4 -target ntsc-vcd FSMs-vcd.mp4  # VCD
ffmpeg -i FSMs.mp4 -target ntsc-svcd FSMs-svcd.mp4  # SVCD

# Transformations
ffmpeg -i FSMs.mp4 -vf vflip -c:a copy FSMs-vflip.mp4  # 
ffmpeg -i FSMs.mp4 -vf hflip -c:a copy FSMs-hflip.mp4
ffmpeg -i FSMs.mp4 -vf transpose=1 -c:a copy FSMs-transpose1.mp4
ffmpeg -i FSMs.mp4 -vf transpose=2 -c:a copy FSMs-transpose2.mp4
ffmpeg -i FSMs.mp4 -vf scale=-1:320 -c:a copy FSMs-320p.mp4
ffmpeg -i FSMs.mp4 -vf scale=320:-1 -c:a copy FSMs-320p.mp4
ffmpeg -i FSMs.mp4 -vf 'scale=-1:320' -c:a copy FSMs-320p.mp4
ffmpeg -i FSMs.mp4 -vf 'scale=-2:320' -c:a copy FSMs-320p.mp4
ffmpeg -i FSMs.mp4 -vf 'scale=iw*.5:-2' -c:a copy FSMs-iw05.mp4
ffmpeg -i FSMs.mp4 -vf 'scale=iw*.5:-1' -c:a copy FSMs-iw05.mp4
ffmpeg -i FSMs.mp4 -vf 'scale=iw*.5:iw*.5' -c:a copy FSMs-iw05.mp4
ffmpeg -i FSMs.mp4 -vf 'scale=iw*.5:ih*.5' -c:a copy FSMs-iw05.mp4
ffmpeg -i FSMs.mp4 -vf 'scale=iw*.5:ih' -c:a copy FSMs-iw05.mp4

# Testing convert and scale images (But not)
ffmpeg -i cover.png cover.jpg
ffmpeg -i cover.jpg -vf scale=200:262 cover_small.jpg
ffmpeg -i cover.jpg -vf scale=200:262 cover_small.png


FFMPEG="nice -n 20 ffmpeg -loglevel error -hide_banner"

$FFMPEG -i "$audio_tempfile" -i "$video_tempfile" -codec copy -map 0:a:0 -map 1:v:0 "$destination"





pactl list short sources


pulse_audio_id="$(pactl list short sources | awk '/usb-Video_Grabber_HDMI_to_U3_capture/ { print $1; exit }')"

video_device="$(find /sys/devices/ -type f -name name -exec grep -l -e '^HDMI to U3 capture$' {} + | awk -F "/" '/video4linux/ { print "/dev/" $(NF - 1); exit }')"




$FFMPEG -f pulse -ac 2 -ar 44100 -i "$pulse_audio_id" -c copy -map 0 "$audio_tempfile"
$FFMPEG -f v4l2 -i "$video_device" -c copy -map 0 "$video_tempfile"

ffmpeg -y -i $first -vn -f u16le -acodec pcm_s16le -ac 2 -ar 44100 $TMP/mcs_a1 2>/dev/null </dev/null &
ffmpeg -y -i $first -an -f yuv4mpegpipe -vcodec rawvideo $TMP/mcs_v1 2>/dev/null </dev/null &

ffmpeg -y -i $f -vn -f u16le -acodec pcm_s16le -ac 2 -ar 44100 $TMP/mcs_a$i 2>/dev/null </dev/null &
	



ffmpeg -i test.avi -r 1/1 $frame%03d.jpg
composite 002.jpg 003.jpg -compose difference  test.jpg

convert 0*.jpg   -background white -compose difference -flatten result.jpg

ffmpeg -i "concat:01.mp3|02.mp3|03.mp3|04.mp3|05.mp3|06.mp3|07.mp3|08.mp3|09.mp3|10.mp3|11.mp3|12.mp3|13.mp3|14.mp3|15.mp3|16.mp3|17.mp3|" -acodec copy output.mp3

ffmpeg -loop 1 -i img.jpeg -i output.mp3 -shortest -acodec copy ubik.mp4



ffmpeg -i "$a" -f wav - | lame --preset insane --add-id3v2 --pad-id3v2 --ignore-tag-errors \
    --ta "Kasabian" --tt "$TITLE" --tl "NYE Re:Wired at The O2" \
--tn "${TRACKNUMBER:-0}" --ty "2011" - "$OUTF"







  ARTIST=$(metaflac "$a" --show-tag=ARTIST | sed s/.*=//g)
  TITLE=$(metaflac "$a" --show-tag=TITLE | sed s/.*=//g)
  ALBUM=$(metaflac "$a" --show-tag=ALBUM | sed s/.*=//g)
  GENRE=$(metaflac "$a" --show-tag=GENRE | sed s/.*=//g)
  TRACKNUMBER=$(metaflac "$a" --show-tag=TRACKNUMBER | sed s/.*=//g)
DATE=$(metaflac "$a" --show-tag=DATE | sed s/.*=//g)


# MP3
avconv -b 192k -i file file.mp3

# MP3
avconv -i file.wav -acodec mp3 -ab 32 -ar 44100 file.mp3

# FLAC
avconv -i file.wav -ab 999k -y file.flac



ffmpeg -y -i ${VIDSOURCE} -c:v ${VCODEC} -s:v ${SIZE} -r:v ${FRAMERATE} -b:a ${ABITRATE}k -ac 2 -c:a ${ACODEC} -b:v ${VBITRATE}k -maxrate ${VBITRATE}k -bufsize ${VBITRATE}k ${PROFILE} ${OUTPUT}



