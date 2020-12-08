#!/bin/sh
##-===============================================================-##
##   
## 
##-===============================================================-##
##   [?] I placed $ infront of the input/output files 
##   [?] (Bash Syntax Highlights it like its a defined function, 
##       so its easy to destinguish for yourself.)
##-===============================================================-##
## 
##   
## 
##   
## 
##   
## 






ffmpeg -codecs






ffmpeg --dump_stream_info


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] AVI File --> MP4 File:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $input.avi $output.mp4


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] MP3 File --> OGG File:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $input.mp3 $output.ogg



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] MP4 File --> WEBM File       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $input.mp4 $output.webm



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] MOV File --> MP4 File       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $Input.mov $Output.mp4


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] MP3 File --> OGG File       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $input.mp3 $output.ogg



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert a .mkv to .webm:         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $input.mkv $output.webm


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert a .mkv to .mp4:         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $input.mkv $output.mp4




echo "##-=====================================-##"
echo "    [+] copy the video stream from:    "
echo "        input.webm --> output.mkv      "
echo "##-=====================================-##"
echo "## ---------------------------------------------------- ##"
echo "    [?] Encode the Vorbis audio stream into a FLAC."
echo "## ---------------------------------------------------- ##"
ffmpeg -i $Input.webm -c:v copy -c:a flac $Output.mkv

ffmpeg -i $Input.webm -c:av copy $Output.mkv



## creates a GIF of the same dimensions as the input file
ffmpeg -i $Input.mkv $Output.gif




echo "##-===========================================================-##"
echo "     [+] Extracts Only The Audio From The .mkv, And               "
echo "         Encodes It As mp3, And Saves It Into $Output.ogg          "
echo "##-===========================================================-##"
ffmpeg -i $Input.mkv -vn $Output.ogg



echo "##-===========================================================-##"
echo "     [+] Extracts Only The Audio From The .mkv, And               "
echo "         Encodes It As mp3, And Saves It Into $Output.mp3          "
echo "##-===========================================================-##"
ffmpeg -i $Input.mkv -vn $Output.mp3


# Extract audio from a video
ffmpeg -i video.avi -f mp3 audio.mp3


echo "##-===========================================================-##"
echo "     [+] Extracts Only The Audio From The .mp4, And               "
echo "         Encodes It As mp3, And Saves It Into $Output.mp3          "
echo "##-===========================================================-##"
ffmpeg -i $Input.mp4 -acodec libmp3lame -b:a 256k -vn $Output.mp3

ffmpeg -i $Input.mp4 -acodec libmp3lame -b:a 192k -vn $Output.mp3

ffmpeg -i $Input.mp4 -acodec libmp3lame -b:a 320k -vn $Output.mp3


ffmpeg -i .mp4 -acodec libmp3lame -b:a 256k -vn .mp3



ffmpeg -i Top_30_Songs_Of_Goblins_From_Mars_Best_of_Goblins_From_Mars_GFM_The_Best_of_all_time_hd720.mp4 -acodec libmp3lame -b:a 256k -vn Top_30_Songs_Of_Goblins_From_Mars_Best_of_Goblins_From_Mars_GFM_The_Best_of_all_time.mp3


ffmpeg -i Top_30_Songs_Of_Goblins_From_Mars_Best_of_Goblins_From_Mars_GFM_The_Best_of_all_time_hd720.mp4 -acodec libmp3lame -b:a 320k -vn Top_30_Songs_Of_Goblins_From_Mars_Best_of_Goblins_From_Mars_GFM_The_Best_of_all_time.mp3










echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Synchronize The Audio And Video:   "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## -------------------------------------------------------------------------------------- ##"
echo "    [?] To ensure that audio and video synchronize during playback insert keyframes.        "
echo "## -------------------------------------------------------------------------------------- ##"
ffmpeg -i myvideo.mp4 -keyint_min 150 -g 150 -f webm -vf setsar=1:1 out.webm








echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] MP4 File --> H.264           "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i myvideo.mp4 -c:v libx264 -c:a copy myvideo.mp4



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Extract The Audio From An MP4 File:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert A WEBMs Audio To VP9:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i myvideo.webm -v:c libvpx-vp9 -v:a copy myvideo.webm



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Copy A Webms Audio Into Another Webm:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i myvideo.webm -v:c copy -v:a libvorbis myvideo.webm
ffmpeg -i myvideo.webm -v:c copy -v:a libopus myvideo.webm









echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] list the supported, connected capture devices:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -y -f vfwcap -i list



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] List device capabilities:          "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -f v4l2 -list_formats all -i /dev/video0


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Encode video from /dev/video0:     "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -f v4l2 -framerate 25 -video_size 640x480 -i /dev/video0 $output.mkv



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Print The Codecs Supported By FFmpeg:        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -codecs


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Send program-friendly progress information:  "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -progress 



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] see if an audio file contains the album cover:         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $input.mp3


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] show the album cover and play the music:         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffplay -i $input.mp3


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] use it as the video For your music that you want to upload to YouTube:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $input.mp3 -c copy $output.mkv



echo "##-=========================-##"
echo "    || -V0 || ~245 kbps ||     "
echo "    || -V1 || ~225 kbps ||     "
echo "    || -V2 || ~190 kbps ||     "
echo "    || -V3 || ~175 kbps ||     "
echo "##-=========================-##"







echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] generate A framemd5 report:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $MOVIE.mov -f framemd5 $MOVIE.framemd5


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Adds -c copy Parameter To The Syntax:        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## -------------------------------------------------------- ##"
echo "    [?] which causes the framemd5 to                          "
echo "    [?] generate checksums of the data                        "
echo "    [?] as it is stored:                                      "
echo "## -------------------------------------------------------- ##"
ffmpeg -i $MOVIE.mov -c copy -f framemd5 $MOVIE.framemd5



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] 2-pass VP9 encoding with FFMpeg:         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## -------------------------------------------------------------------------------------------- ##"
echo "    [?] c:v libvpx-vp9 - tells FFmpeg to encode the video in VP9:                                 "
echo "    [?] c:a libopus    - tells FFmpeg to encode the audio in Opus:                                "
echo "    [?] b:v 1000K      - tells FFmpeg to encode the video with a target of 1000 kilobits:         "
echo "    [?] b:a 64k        - tells FFmpeg to encode the audio with a target of 64 kilobits:           "
echo "## -------------------------------------------------------------------------------------------- ##"

ffmpeg -i $Source -c:v libvpx-vp9 -pass 1 -b:v 1000K -threads 8 -speed 4 -tile-columns 6 -frame-parallel 1 -an -f webm /dev/null

ffmpeg -i $Source -c:v libvpx-vp9 -pass 2 -b:v 1000K -threads 8 -speed 1 -tile-columns 6 -frame-parallel 1 -auto-alt-ref 1 -lag-in-frames 25 -c:a libopus -b:a 64k -f webm $out.webm





echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Best Quality (Slowest) Recommended Settings:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $Source -c:v libvpx-vp9 -pass 1 -b:v 1000K -threads 1 -speed 4 -tile-columns 0 -frame-parallel 0 -g 9999 -aq-mode 0 -an -f webm /dev/null



ffmpeg -i $Source -c:v libvpx-vp9 -pass 2 -b:v 1000K -threads 1 -speed 0 -tile-columns 0 -frame-parallel 0 -auto-alt-ref 1 -lag-in-frames 25 -g 9999 -aq-mode 0 -c:a libopus -b:a 64k -f webm $out.webm





echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Extract images from a video:         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $foo.avi -r 1 -s WxH -f image2 $foo-%03d.jpeg



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Grab the X11 display with ffmpeg:        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -f x11grab -video_size cif -framerate 25 -i :0.0 /tmp/$out.mpg



echo "## -------------------------------------------------------------- ##"
echo "    [?] 0.0 is display.screen number of your X11 server,            "
echo "    [?] same as the DISPLAY environment variable.                   "
echo "## -------------------------------------------------------------- ##"
ffmpeg -f x11grab -video_size cif -framerate 25 -i :0.0+10,20 /tmp/$out.mpg








echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Global Metadata in WebM:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"






echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] WebVTT Metadata Common To WebM:        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"










echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] get a list of the filters:     "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -filters



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Use filters to create effects and to add text:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $input.mp3 -filter_complex "[0:a]avectorscope=s=640x518[left]; [0:a]showspectrum=mode=separate:color=intensity:scale=cbrt:s=640x518[right]; [0:a]showwaves=s=1280x202:mode=line[bottom]; [left][right]hstack[top]; [top][bottom]vstack,drawtext=fontfile=/usr/share/fonts/TTF/Vera.ttf:fontcolor=white:x=10:y=10:text='\"Song Title\" by Artist'[out]" -map "[out]" -map 0:a -c:v libx264 -preset fast -crf 18 -c:a copy $output.mkv



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Show The .mp4 File's Data Streams:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffprobe -v error -show_format -show_streams $input.mp4





echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Determine The Videos Frame Rate:         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffprobe -v error -select_streams v:0 -show_entries stream=avg_frame_rate -of default=noprint_wrappers=1:nokey=1 $input.mp4



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Determine The Videos Width x Height (resolution):            "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffprobe -v error -select_streams v:0 -show_entries stream=height,width -of csv=s=x:p=0 $input.mp4








echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Concatenating media files:         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -f concat -safe 0 -i <(for f in ./*.wav; do echo "file '$PWD/$f'"; done) -c copy $output.wav
ffmpeg -f concat -safe 0 -i <(printf "file '$PWD/%s'\n" ./*.wav) -c copy $output.wav
ffmpeg -f concat -safe 0 -i <(find . -name '*.wav' -printf "file '$PWD/%p'\n") -c copy $output.wav


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] loop input.mkv 10 times:           "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
for i in {1..10}; do printf "file '%s'\n" $input.mkv >> $List.txt; done
ffmpeg -f concat -i $List.txt -c copy $output.mkv



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Concatenate three MPEG-2 TS files:               "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## --------------------------------------------------- ##"
echo "    [?] And concatenates them without re-encoding:       "
echo "## --------------------------------------------------- ##"
ffmpeg -i "concat:$input1.ts|$input2.ts|$input3.ts" -c copy $output.ts



echo "##-========================================================-##"
echo "## -------------------------------------------------------- ##"
echo "    [?] If you have MP4 files                                 "
echo "    [?] these could be losslessly concatenated                "
echo "    [?] by first transcoding them to MPEG-2 transport streams."
echo "    [?] With H.264 video and AAC audio:                       "
echo "## -------------------------------------------------------- ##"
echo "##-========================================================-##"
ffmpeg -i $input1.mp4 -c copy -bsf:v h264_mp4toannexb -f mpegts $intermediate1.ts
ffmpeg -i $input2.mp4 -c copy -bsf:v h264_mp4toannexb -f mpegts $intermediate2.ts
ffmpeg -i "concat:$intermediate1.ts|$intermediate2.ts" -c copy -bsf:a aac_adtstoasc $output.mp4



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Concatenation of files with different codecs         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## ------------------------------------------------------- ##"
echo "    [?] three files that we want to concatenate              "
echo "    [?] each of them with one video and audio stream         "
echo "## ------------------------------------------------------- ##"
ffmpeg -i $input1.mp4 -i $input2.webm -i $input3.mov -filter_complex "[0:v:0][0:a:0][1:v:0][1:a:0][2:v:0][2:a:0]concat=n=3:v=1:a=1[outv][outa]" -map "[outv]" -map "[outa]" $output.mkv





echo "## ------------------------------------------------ ##"
echo "    [?] When converting to an MP4,                    "
echo "    [?] you want to use the h264 video codec          "
echo "    [?] and the aac audio codec                       "
echo "## ------------------------------------------------ ##"
ffmpeg -i $input.mov -vcodec h264 -acodec aac -strict -2 $output.mp4






echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] input.mov is converted to output.webm          "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## ------------------------------------------------- ##"
echo "    [?] with a constant rate factor of 10              "
echo "    [?] (lower is higher quality)                      "
echo "    [?] at a bitrate of 1M                             "
echo "## ------------------------------------------------- ##"




echo "## --------------------------------------------------------------- ##"
echo "   [?] If your video does not have audio, you may leave off:         "
echo "                 -->  '-acodec libvorbis'                            "
echo "## --------------------------------------------------------------- ##"




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Set the audio stream to be Vorbis:     "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $input.mp3 -c:a libvorbis output.ogg




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Make a Matroska container:         " 
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## ----------------------------------------- ##"
echo "    [?] with a VP9 video stream                "
echo "    [?] and a Vorbis audio stream              "
echo "## ----------------------------------------- ##"
ffmpeg -i $input.mp4 -c:v vp9 -c:a libvorbis $output.mkv




echo "##-========================================================-##"
echo "## -------------------------------------------------------- ##"
echo "   [?] The -c Flag - copies the video stream from             "
echo "   [?] input.webm into output.mkv and encodes                 "
echo "   [?] the Vorbis audio stream into a FLAC.                   "
echo "## -------------------------------------------------------- ##"
echo "##-========================================================-##"
ffmpeg -i $input.webm -c:v copy -c:a flac $output.mkv




echo "##-========================================================-##"
echo "## -------------------------------------------------------- ##"
echo "    [?] convert from one container format                     "
echo "    [?] to another without having to do any                   "
echo "    [?] additional stream encoding:                           "
echo "## -------------------------------------------------------- ##"
echo "##-========================================================-##"
ffmpeg -i $input.webm -c:av copy $output.mkv




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] writing A ID3v2.3 header:        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## -------------------------------------------------------- ##"
echo "    [?] instead of a default ID3v2.4 to an MP3 file,          "
echo "    [?] use the id3v2_version                                 "
echo "    [?] private option of the MP3 muxer:                      "
echo "## -------------------------------------------------------- ##"
ffmpeg -i $input.flac -id3v2_version 3 $out.mp3




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Modify The LogLevel, So Debug Info Is Printed:         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -loglevel repeat+level+verbose -i input output




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] print metadata about a video file:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i input_file -f ffmetadata $metadata.txt




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Extracting an ffmetadata file with ffmpeg goes as follows:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i INPUT -f ffmetadata FFMETADATAFILE



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Reinserting edited metadata information            "
echo "    [?] From the FFMETADATAFILE file:                      "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i INPUT -i FFMETADATAFILE -map_metadata 1 -codec copy OUTPUT




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert a .mkv to .webm:         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $input.mkv $output.webm



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] A more detailed ffmpeg conversion:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $input.mp4 -c:v libvpx-vp9 -b:v 1M -c:a libvorbis $output.webm





echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] take all data from the time specified at START.            "
echo "    [?] It starts transcoding from the specified time instantly,   "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -ss START -i "INPUT.mkv" $output.webm
ffmpeg -i "INPUT.mkv" -ss START $output.webm




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Extract a snippet of video:        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -ss START -t DURATION
ffmpeg -ss START -to END





echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Joining Video Files together:        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## --------------------------------------- ##"
echo "    [?] create a text file                   "
echo "    [?] containing names of the files:       "
echo "## --------------------------------------- ##"
ffmpeg -f concat -i $File.txt -c copy $output.webm




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Server side (sending):       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $File.ogg -c copy -listen 1 -f ogg http://server:port



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Client side (receiving):       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i http://server:port -c copy $File.ogg



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Client can also be done with wget:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
wget http://server:port -O $File.ogg



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Server side (receiving):       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -listen 1 -i http://server:port -c copy $File.ogg



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Client side (sending):       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $somefile.ogg -chunked_post 0 -c copy -f ogg http://server:port



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Client can also be done with wget:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
wget --post-file=$File.ogg http://server:port




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert a GIF file given inline with ffmpeg:         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i "data:image/gif;base64,R0lGODdhCAAIAMIEAAAAAAAA//8AAP//AP///////////////ywAAAAACAAIAAADF0gEDLojDgdGiJdJqUX02iB4E8Q9jUMkADs=" smiley.png




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Read a sequence of files         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## --------------------------------------------- ##"
echo "    [?] split1.mpeg, split2.mpeg, split3.mpeg      "
echo "    [?] with ffplay use the command:               "
echo "## --------------------------------------------- ##"
ffplay concat:$split1.mpeg\|$split2.mpeg\|$split3.mpeg





echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Create MP3 audio files (ffmpeg has no native MP3 encoder).       "
echo "    [?] Encode VBR MP3 audio with ffmpeg using the libmp3lame library:   "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i $input.wav -codec:a libmp3lame -qscale:a 2 $output.mp3











echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Re-encode the video and stream copy the audio.         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## -------------------------------------------------------------- ##"
echo "    [?] The output should be a similar quality as the input         "
echo "    [?] and should be a more manageable size.                       "
echo "## -------------------------------------------------------------- ##"
ffmpeg -i $input.avi -c:v libx264 -preset slow -crf 18 -c:a copy -pix_fmt yuv420p $output.mkv


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Re-encode the audio:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## ----------------------------------------------- ##"
echo "    [?] using AAC instead of stream copying it:      "
echo "## ----------------------------------------------- ##"
ffmpeg -i $input.mov -c:v libx264 -preset slow -crf 18 -c:a aac -b:a 192k -pix_fmt yuv420p $output.mkv





echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Create a video with a still image (input.png):         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## ----------------------------------------------- ##"
echo "    [?] And an audio file (audio.m4a):               "
echo "## ----------------------------------------------- ##"
ffmpeg -loop 1 -framerate 2 -i $input.png -i $audio.m4a -c:v libx264 -preset medium -tune stillimage -crf 18 -c:a copy -shortest -pix_fmt yuv420p output.mkv













## Copy metadata from the first stream of the input file 
## To global metadata of the output file:
ffmpeg -i in.ogg -map_metadata 0:s:0 out.mp3


## Copy global metadata to all audio streams:
ffmpeg -i in.mkv -map_metadata:s:a 0:g out.mkv





ffmpeg -dump 
## Dump each input packet to stderr.

ffmpeg -hex 
## When dumping packets, also dump the payload. (global)

-copy_unknown



-vstats
-vstats_file file




extract the first attachment to a file named 'out.ttf':

ffmpeg -dump_attachment:t:0 out.ttf -i INPUT

To extract all attachments to files determined by the "filename" tag:

ffmpeg -dump_attachment:t "" -i INPUT





echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Add extradata to the beginning of the filtered packets:        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"

ffmpeg -i INPUT -map 0 -flags:v +global_header -c:v libx264 -bsf:v dump_extra $out.ts

ffmpeg -i INPUT.mp4 -codec copy -bsf:v h264_mp4toannexb OUTPUT.ts


ffmpeg -i INPUT -c:v copy -bsf:v 'filter_units=remove_types=35|38-40' OUTPUT



ffmpeg -i INPUT -c copy -bsf noise[=1] output.mkv






ffmpeg -i img.jpeg img.png







ffmpeg -i INPUT -f ffmetadata FFMETADATAFILE
ffmpeg -i INPUT -i FFMETADATAFILE -map_metadata 1 -codec copy OUTPUT





## Video and Audio grabbing

## If you specify the input format and device then ffmpeg can grab video and audio directly.
ffmpeg -f oss -i /dev/dsp -f video4linux2 -i /dev/video0 /tmp/out.mpg



## Or with an ALSA audio source (mono input, card id 1) instead of OSS:
ffmpeg -f alsa -ac 1 -i hw:1 -f video4linux2 -i /dev/video0 /tmp/out.mpg


ffmpeg -i INPUT.avi -codec copy -bsf:v mpeg4_unpack_bframes OUTPUT.avi


## fix an AVI file containing an MPEG-4 stream with DivX-style packed B-frames
ffmpeg -i INPUT.avi -codec copy -bsf:v mpeg4_unpack_bframes OUTPUT.avi





## show only audio streams, you can use the command:
ffprobe -show_streams -select_streams a INPUT


## To show only video packets belonging to the video stream with index 1:
ffprobe -show_packets -select_streams v:1 INPUT


mjpegadump
## Add an MJPEG A header to the bitstream, to enable decoding by Quicktime.

mov2textsub
## Extract a representable text file from MOV subtitles, stripping the metadata header from each subtitle packet.

This bitstream filter patches the header of frames extracted from an MJPEG stream (carrying the AVI1 header ID and
lacking a DHT segment) to produce fully qualified JPEG images.

ffmpeg -i mjpeg-movie.avi -c:v copy -bsf:v mjpeg2jpeg frame_%d.jpg
exiftran -i -9 frame*.jpg
ffmpeg -i frame_%d.jpg -c:v copy rotated.avi






extract_extradata
## Extract the in-band extradata.

## Certain codecs allow the long-term headers 
## (e.g. MPEG-2 sequence headers, 
## or H.264/HEVC (VPS/)SPS/PPS) 
## to be transmitted either 
## "in-band" (as a part of the bitstream containing the coded frames) 
## or "out of band" (on the container level). 
## This latter form is called "extradata" in FFmpeg terminology.




## Remove zero padding at the end of a packet.
chomp


## Extract the core from a DCA/DTS stream, dropping extensions such as DTS-HD.
dca_core


dump_extra


## Add extradata to the beginning of the filtered packets.
## The additional argument specifies which packets should be filtered.

## a        ## add extradata to all key packets, but only if local_header is set in the flags2 codec context field
## k        ## add extradata to all key packets
## e        ## add extradata to all packets

##-====================================================================================-##
##                  (If not specified it is assumed k)
##-====================================================================================-##
## forces a global header (thus disabling individual packet headers) in the
## H.264 packets generated by the "libx264" encoder, 
## but corrects them by adding the header stored in extradata to the key packets:

ffmpeg -i INPUT -map 0 -flags:v +global_header -c:v libx264 -bsf:v dump_extra out.ts














ffmpeg -i ../some_mjpeg.avi -c:v copy frames_%d.jpg



ffplay -f video4linux2 -list_formats all /dev/video0
ffplay -f video4linux2 -framerate 30 -video_size hd720 /dev/video0


ffplay -i input -vf histogram



ffplay -dumpgraph 1 -f lavfi


ffplay -report
ffplay -loglevel verbose








echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Read A Rawvideo File $input.raw With ffplay:           "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## --------------------------------------------------------- ##"
echo "    [?] Assuming A Pixel Format of rgb24                       "
echo "    [?] A Video Size of 320x240                                "
echo "    [?] And A Frame Rate of 10 Images Per Second               "
echo "## --------------------------------------------------------- ##"
ffplay -f rawvideo -pixel_format rgb24 -video_size 320x240 -framerate 10 $input.raw




echo "##-=========================================-##"
echo "## ----------------------------------------- ##"
echo "    [?] With The Overlay Filter,               "
echo "    [+] Place An Infinitely Looping GIF        "
echo "    [?] Over Another Video:                    "
echo "## ----------------------------------------- ##"
echo "##-=========================================-##"
ffmpeg -i $input.mp4 -ignore_loop 0 -i $input.gif -filter_complex overlay=shortest=1 $out.mkv




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Extract the first attachment to a file named 'out.ttf':        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -dump_attachment:t:0 $out.ttf -i INPUT



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Extract all attachments to files determined by the "filename" tag:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -dump_attachment:t "" -i INPUT







ffmpeg -vstats                  ## Dump video coding statistics to vstats_HHMMSS.log.
ffmpeg -vstats_file $file       ## Dump video coding statistics to file.









ffmpeg -f flv -i $myfile.flv ...
ffmpeg -f live_flv -i rtmp://<any.server>/anything/key ....

-flv_metadata bool              ## Allocate the streams according to the onMetaData array content.
-flv_ignore_prevtag bool        ## Ignore the size of previous tag value.
-flv_full_metadata bool         ## Output all context of the onMetadata. 




ffmpeg -f flv -i myfile.flv






ffmpeg -minrate -i $input.flac -id3v2_version 3 $out.mp3


ffmpeg -minrate -i $File.mp4 $File.mp3 	    ## Minimal bitrate allowed in vbr/2pass mode 	
ffmpeg -maxrate 	                        ## Maxium bitrate allowed in vbr/2pass mode



Two-Pass Encoding

ffmpeg -y -i input -c:v libx265 -b:v 2600k -x265-params pass=1 -an -f mp4 /dev/null && \
ffmpeg -i input -c:v libx265 -b:v 2600k -x265-params pass=2 -c:a aac -b:a 128k $output.mp4




Constant Rate Factor (CRF)

ffmpeg -i input -c:v libx265 -crf 28 -c:a aac -b:a 128k $output.mp4




encodes a video with good quality, using slower preset to achieve better compression:

ffmpeg -i $input.avi -c:v libx264 -preset slow -crf 22 -c:a copy $output.mkv




## Fast encoding example:
ffmpeg -i input -c:v libx264 -preset ultrafast -crf 0 $output.mkv


## Best compression example:
ffmpeg -i input -c:v libx264 -preset veryslow -crf 0 $output.mkv




list recording cards or devices:
arecord -l
arecord -L


## Capturing audio with ffmpeg and ALSA
ffmpeg -f alsa <input_options> -i <input_device> ... $output.wav
ffmpeg -f alsa -i default:CARD=U0x46d0x809 -t 30 $out.wav

## 30 seconds WAV audio output, 
## recorded from our USB camera's 
## default recording device (microphone).
ffmpeg -f alsa -i hw:1 -t 30 $out.wav
ffmpeg -f alsa -i hw:0,2 -t 30 $out.wav


## Record audio from an application ¶

## Record audio from an application
## Load the snd_aloop module:
modprobe snd-aloop pcm_substreams=1

## Set the default ALSA audio output 
## to one substream of the Loopback device 
## in your .asoundrc (or /etc/asound.conf)


## Edit The .asoundrc File:
pcm.!default { type plug slave.pcm "hw:Loopback,0,0" }


## You can now record audio from a running application using:
ffmpeg -f alsa -ac 2 -ar 44100 -i hw:Loopback,1,0 $out.wav





mp4/ffmpeg

ffmpeg -i myvideo.mp4 -vcodec copy -an myvideo_video.mp4
ffmpeg -i myvideo.mp4 -acodec copy -vn myvideo_audio.m4a

webm/ffmpeg

ffmpeg -i myvideo.webm -vcodec copy -an myvideo_video.webm
ffmpeg -i myvideo.webm -acodec copy -vn myvideo_audio.webm


MP3 file and want it converted into an OGG file:

ffmpeg -i input.mp3 output.ogg


Change characteristics
Bitrate

For ffmpeg, I can do this while Im converting to mp4 or webm.

ffmpeg -i myvideo.mov -b:v 350K myvideo.mp4
ffmpeg -i myvideo.mov -vf setsar=1:1 -b:v 350K myvideo.webm



mov to mp4

ffmpeg -i myvideo.mov myvideo.mp4


When converting a file to webm, 
ffmpeg doesnt provide the correct aspect ratio. 
Fix this with a filter (-vf setsar=1:1).

ffmpeg -i myvideo.mov -vf setsar=1:1 myvideo.webm



Resolution

ffmpeg -i $video.webm -s 1920x1080 $video_1920x1080.webm      ## set frame size (WxH or abbreviation)




ffmpeg -i $video.$ext -metadata string=$String


setting the title in the output file:

ffmpeg -i in.avi -metadata title="my title" out.flv




for Matroska you also have to set the mimetype metadata tag:

ffmpeg -i INPUT -attach DejaVuSans.ttf -metadata:s:2 mimetype=application/x-truetype-font out.mkv




extract all attachments to files determined by the "filename" tag:

ffmpeg -dump_attachment:t "" -i INPUT



Create 5 copies of the input audio with ffmpeg:

ffmpeg -i INPUT -filter_complex asplit=5 OUTPUT





-dn                 disable data

-seek_timestamp     enable/disable seeking by timestamp with -ss
-timestamp time     set the recording timestamp ('now' to set the current time)
-metadata string=string  add metadata
-map_metadata outfile[,metadata]:infile[,metadata]  set metadata information of outfile from infile


-stats              print progress report during encoding
-ignore_unknown     Ignore unknown stream types
-report             generate a report
-loglevel 
-sources device     list sources of the input device

-buildconf          show build configuration
-formats            show available formats
-muxers             show available muxers
-demuxers           show available demuxers
-devices            show available devices
-codecs             show available codecs
-decoders           show available decoders
-encoders           show available encoders
-bsfs               show available bit stream filters
-protocols          show available protocols
-filters            show available filters






icecast://[username[:password]@]server:port/mountpoint




write an ID3v2.3 header instead of a default ID3v2.4 to an MP3 file
use the id3v2_version private option of the MP3 muxer:

ffmpeg -i input.flac -id3v2_version 3 out.mp3


show only audio streams
ffprobe -show_streams -select_streams a INPUT



show only video packets belonging to the video stream with index 1:
ffprobe -show_packets -select_streams v:1 INPUT



read a sequence of files split1.mpeg, split2.mpeg, split3.mpeg with ffplay use the command:

               ffplay concat:split1.mpeg\|split2.mpeg\|split3.mpeg






enables experimental HTTP server. This can be used to send data when used as an output
           option, or read data from a client with HTTP POST when used as an input option.  If set to 2 enables
           experimental multi-client HTTP server.

                   # Server side (sending):
                   ffmpeg -i somefile.ogg -c copy -listen 1 -f ogg http://<server>:<port>

                   # Client side (receiving):
                   ffmpeg -i http://<server>:<port> -c copy somefile.ogg

                   # Client can also be done with wget:
                   wget http://<server>:<port> -O somefile.ogg

                   # Server side (receiving):
                   ffmpeg -listen 1 -i http://<server>:<port> -c copy somefile.ogg

                   # Client side (sending):
                   ffmpeg -i somefile.ogg -chunked_post 0 -c copy -f ogg http://<server>:<port>

                   # Client can also be done with wget:
                   wget --post-file=somefile.ogg http://<server>:<port>





HTTP Cookies

ffplay -cookies "nlqptid=nltid=tsn; path=/; domain=somedomain.com;" http://somedomain.com/somestream.m3u8





ice_url
ice_name
user_agent
password


icecast://[<username>[:<password>]@]<server>:<port>/<mountpoint>




               # Write the MD5 hash of the encoded AVI file to the file output.avi.md5.
               ffmpeg -i input.flv -f avi -y md5:output.avi.md5

               # Write the MD5 hash of the encoded AVI file to stdout.
               ffmpeg -i input.flv -f avi -y md5:






Read from or write to remote resources using SFTP protocol



sftp://[user[:password]@]server[:port]/path/to/remote/resource.mpeg


private_key ~/.ssh/


Play a file stored on remote server.

ffplay sftp://user:password@server_address:22/home/user/resource.mpeg






Transport Layer Security (TLS) / Secure Sockets Layer (SSL)

The required syntax for a TLS/SSL url is:

tls://<hostname>:<port>[?<options>]

                        ##-=======================================================-##
                        ##   [+] 
                        ##-=======================================================-##
cafile=                 ## [+] A file containing certificate authority (CA) 
                        ##     root certificates to treat as trusted.
                        ##-=======================================================-##
                        
                        ##-=======================================================-##
tls_verify=1            ##   [+] Verify the peer that we are communicating with
                        ##-=======================================================-##
cert=                   ## A file containing a certificate to use in the handshake with the peer.
                        ##-=================================================-##
                        
                        ## ------------------------------------------------- ##
                        ##   [?] When operating as server, in listen mode
                        ##       this is more often required by the peer
                        ## ------------------------------------------------- ##
















read from stdin with ffmpeg:

               cat test.wav | ffmpeg -i pipe:0
               # ...this is the same as...
               cat test.wav | ffmpeg -i pipe:


writing to stdout with ffmpeg:

               ffmpeg -i test.wav -f avi pipe:1 | cat > test.avi
               # ...this is the same as...
               ffmpeg -i test.wav -f avi pipe: | cat > test.avi























































man ffprobe-all | grep "ffmpeg -"
ffmpeg -sources pulse,server=192.168.0.4
ffmpeg -sinks pulse,server=192.168.0.4

##  output a report to a file named ffreport.log using a log level of 32 (alias for log level "info"
FFREPORT=file=ffreport.log:level=32 ffmpeg -i input output
ffmpeg -cpuflags -sse+mmx ...
ffmpeg -cpuflags mmx ...
ffmpeg -cpuflags 0 ...
ffmpeg -opencl_bench
ffmpeg -opencl_options platform_idx=<pidx>:device_idx=<didx> ...
ffmpeg -i input.flac -id3v2_version 3 out.mp3
ffmpeg -i INPUT -c:v copy -bsf:v filter1[=opt1=str1:opt2=str2][,filter2] OUTPUT
ffmpeg -i INPUT -map 0 -flags:v +global_header -c:v libx264 -bsf:v dump_extra out.ts
ffmpeg -i INPUT.mp4 -codec copy -bsf:v h264_mp4toannexb OUTPUT.ts
ffmpeg -i INPUT.mp4 -codec copy -bsf:v hevc_mp4toannexb OUTPUT.ts
ffmpeg -i input.mxf -c copy -bsf:v imxdump -tag:v mx3n output.mov
ffmpeg -i ../some_mjpeg.avi -c:v copy frames_%d.jpg
ffmpeg -i mjpeg-movie.avi -c:v copy -bsf:v mjpeg2jpeg frame_%d.jpg
ffmpeg -i frame_%d.jpg -c:v copy rotated.avi
ffmpeg -i INPUT.avi -codec copy -bsf:v mpeg4_unpack_bframes OUTPUT.avi
ffmpeg -i INPUT -c copy -bsf noise[=1] output.mkv
ffmpeg -f flv -i myfile.flv ...
ffmpeg -f live_flv -i rtmp://<any.server>/anything/key ....
ffmpeg -i input.mp4 -ignore_loop 0 -i input.gif -filter_complex overlay=shortest=1 out.mkv
ffmpeg -i img.jpeg img.png
ffmpeg -framerate 10 -i 'img-%03d.jpeg' out.mkv
ffmpeg -framerate 10 -start_number 100 -i 'img-%03d.jpeg' out.mkv
ffmpeg -framerate 10 -pattern_type glob -i "*.png" out.mkv
ffmpeg -i http://www.ted.com/talks/subtitles/id/1/lang/en talk1-en.srt
ffmpeg -i INPUT -f ffmetadata FFMETADATAFILE
ffmpeg -i INPUT -i FFMETADATAFILE -map_metadata 1 -codec copy OUTPUT
ffmpeg -i "data:image/gif;base64,R0lGODdhCAAIAMIEAAAAAAAA//8AAP//AP///////////////ywAAAAACAAIAAADF0gEDLojDgdGiJdJqUX02iB4E8Q9jUMkADs=" smiley.png
ffmpeg -i file:input.mpeg output.mpeg
ffmpeg -i somefile.ogg -c copy -listen 1 -f ogg http://<server>:<port>
ffmpeg -i http://<server>:<port> -c copy somefile.ogg
ffmpeg -listen 1 -i http://<server>:<port> -c copy somefile.ogg
ffmpeg -i somefile.ogg -chunked_post 0 -c copy -f ogg http://<server>:<port>
ffmpeg -i input.flv -f avi -y md5:output.avi.md5
ffmpeg -i input.flv -f avi -y md5:
cat test.wav | ffmpeg -i pipe:0
cat test.wav | ffmpeg -i pipe:
ffmpeg -i test.wav -f avi pipe:1 | cat > test.avi
ffmpeg -i test.wav -f avi pipe: | cat > test.avi
ffmpeg -re -i <input> -f flv -rtmp_playpath some/long/path -rtmp_app long/app/name rtmp://username:password@myserver/
ffmpeg -re -i myfile -f flv rtmp://myserver/live/mystream
ffmpeg -re -i <input> -f rtsp -muxdelay 0.1 rtsp://server/live.sdp
ffmpeg -rtsp_flags listen -i rtsp://ownaddress/live.sdp <output>
ffmpeg -re -i <input> -f sap sap://224.0.0.255?same_port=1
ffmpeg -re -i <input> -f sap sap://224.0.0.255
ffmpeg -re -i <input> -f sap sap://[ff0e::1:2:3:4]
ffmpeg -i <input> -f <format> tcp://<hostname>:<port>?listen
ffmpeg -i <input> -f <format> tls://<hostname>:<port>?listen&cert=<server.crt>&key=<server.key>
ffmpeg -i <input> -f <format> udp://<hostname>:<port>
ffmpeg -i <input> -f mpegts udp://<hostname>:<port>?pkt_size=188&buffer_size=65535
ffmpeg -i udp://[<multicast-address>]:<port> ...
ffmpeg -f alsa -i hw:0 alsaout.wav
ffmpeg -f avfoundation -list_devices true -i ""
ffmpeg -f avfoundation -i "0:0" out.avi
ffmpeg -f avfoundation -video_device_index 2 -i ":1" out.avi
ffmpeg -f avfoundation -pixel_format bgr0 -i "default:none" out.avi
ffmpeg -f decklink -list_devices 1 -i dummy
ffmpeg -f decklink -list_formats 1 -i 'Intensity Pro'
ffmpeg -format_code Hi50 -f decklink -i 'Intensity Pro' -c:a copy -c:v copy output.avi
ffmpeg -bm_v210 1 -format_code Hi50 -f decklink -i 'UltraStudio Mini Recorder' -c:a copy -c:v copy output.avi
ffmpeg -channels 16 -format_code Hi50 -f decklink -i 'UltraStudio Mini Recorder' -c:a copy -c:v copy output.avi
ffmpeg -f kmsgrab -i - -vf 'hwdownload,format=bgr0' output.mp4
ffmpeg -crtc_id 42 -framerate 60 -f kmsgrab -i - -vf 'hwmap=derive_device=vaapi,scale_vaapi=w=1920:h=1080:format=nv12' -c:v h264_vaapi output.mp4
ffmpeg -f libndi_newtek -find_sources 1 -i dummy
ffmpeg -f libndi_newtek -i "DEV-5.INTERNAL.M1STEREO.TV (NDI_SOURCE_NAME_1)" -f libndi_newtek -y NDI_SOURCE_NAME_2
ffmpeg -list_devices true -f dshow -i dummy
ffmpeg -f dshow -i video="Camera"
ffmpeg -f dshow -video_device_number 1 -i video="Camera"
ffmpeg -f dshow -i video="Camera":audio="Microphone"
ffmpeg -list_options true -f dshow -i video="Camera"
ffmpeg -f dshow -audio_pin_name "Audio Out" -video_pin_name 2 -i video=video="@device_pnp_\\?\pci#ven_1a0a&dev_6200&subsys_62021461&rev_01#4&e2c7dd6&0&00e1#{65e8773d-8f56-11d0-a3b9-00a0c9223196}\{ca465100-deb0-4d59-818f-8c477184adf6}":audio="Microphone"
ffmpeg -f dshow -show_video_device_dialog true -crossbar_video_input_pin_number 0
ffmpeg -f fbdev -framerate 10 -i /dev/fb0 out.avi
ffmpeg -f fbdev -framerate 1 -i /dev/fb0 -frames:v 1 screenshot.jpeg
ffmpeg -f gdigrab -framerate 6 -i desktop out.mpg
ffmpeg -f gdigrab -framerate 6 -offset_x 10 -offset_y 20 -video_size vga -i desktop out.mpg
ffmpeg -f gdigrab -framerate 6 -i title=Calculator out.mpg
ffmpeg -f gdigrab -show_region 1 -framerate 6 -video_size cif -offset_x 10 -offset_y 20 -i desktop out.mpg
ffmpeg -f iec61883 -i auto -hdvbuffer 100000 out.mpg
ffmpeg -f jack -i ffmpeg -y out.wav
ffmpeg -f lavfi -i "movie=test.ts[out0+subcc]" -map v frame%08d.png -map s -c copy -f rawvideo subcc.bin
ffmpeg -f libcdio -i /dev/sr0 cd.wav
ffmpeg -list_devices true -f openal -i dummy out.ogg
ffmpeg -f openal -i 'DR-BT101 via PulseAudio' out.ogg
ffmpeg -f openal -i '' out.ogg
ffmpeg -f openal -i 'DR-BT101 via PulseAudio' out1.ogg -f openal -i 'ALSA Default' out2.ogg
ffmpeg -f oss -i /dev/dsp /tmp/oss.wav
ffmpeg -f pulse -i default /tmp/pulse.wav
ffmpeg -f sndio -i /dev/audio0 /tmp/oss.wav
ffmpeg -f video4linux2 -input_format mjpeg -i /dev/video0 out.mpeg
ffmpeg -f x11grab -framerate 25 -video_size cif -i :0.0 out.mpg
ffmpeg -f x11grab -framerate 25 -video_size cif -i :0.0+10,20 out.mpg
ffmpeg -f x11grab -follow_mouse centered -framerate 25 -video_size cif -i :0.0 out.mpg
ffmpeg -f x11grab -follow_mouse 100 -framerate 25 -video_size cif -i :0.0 out.mpg
ffmpeg -f x11grab -show_region 1 -framerate 25 -video_size cif -i :0.0+10,20 out.mpg
ffmpeg -f x11grab -follow_mouse centered -show_region 1 -framerate 25 -video_size cif -i :0.0 out.mpg
ffmpeg -i INPUT -vf "split [main][tmp]; [tmp] crop=iw:ih/2:0:0, vflip [flip]; [main][flip] overlay=0:H/2" OUTPUT
ffmpeg -i infile -vf scale=640:360 outfile
##  [?] See "ffmpeg -filters" to view which filters have timeline support.
ffmpeg -i first.flac -i second.flac -filter_complex acrossfade=d=10:c1=exp:c2=exp output.flac
ffmpeg -i first.flac -i second.flac -filter_complex acrossfade=d=10:o=0:c1=exp:c2=exp output.flac
ffmpeg -i input.wav -i middle_tunnel_1way_mono.wav -lavfi afir output.wav
ffmpeg -i input.mkv -filter_complex "[0:1][0:2][0:3][0:4][0:5][0:6] amerge=inputs=6" -c:a pcm_s16le output.mkv
ffmpeg -i INPUT1 -i INPUT2 -i INPUT3 -filter_complex amix=inputs=3:duration=first:dropout_transition=3 OUTPUT

ffmpeg -shortest     ## extend audio streams to the same length as the video

ffmpeg -i VIDEO -i AUDIO -filter_complex "[1:0]apad" -shortest OUTPUT
ffmpeg -i INPUT -af atrim=60:120
ffmpeg -i INPUT -af atrim=end_sample=1000
ffmpeg -i in.mov -filter 'channelmap=map=DL-FL|DR-FR' out.wav
ffmpeg -i in.wav -filter 'channelmap=1|2|0|5|3|4:5.1' out.wav
ffmpeg -i in.mp3 -filter_complex channelsplit out.mkv
ffmpeg -i in.wav -filter_complex
ffmpeg -i HDCD16.flac -af hdcd OUT24.flac
ffmpeg -i HDCD16.wav -af hdcd OUT16.wav
ffmpeg -i HDCD16.wav -af hdcd -c:a pcm_s24le OUT24.wav
ffmpeg -i input.wav -lavfi-complex "amovie=azi_270_ele_0_DFC.wav[sr],amovie=azi_90_ele_0_DFC.wav[sl],amovie=azi_225_ele_0_DFC.wav[br],amovie=azi_135_ele_0_DFC.wav[bl],amovie=azi_0_ele_0_DFC.wav,asplit[fc][lfe],amovie=azi_35_ele_0_DFC.wav[fl],amovie=azi_325_ele_0_DFC.wav[fr],[a:0][fl][fr][fc][lfe][bl][br][sl][sr]headphone=FL|FR|FC|LFE|BL|BR|SL|SR"
ffmpeg -i INPUT1 -i INPUT2 -i INPUT3 -filter_complex join=inputs=3 OUTPUT
ffmpeg -i fl -i fr -i fc -i sl -i sr -i lfe -filter_complex
ffmpeg -i main.flac -i sidechain.flac -filter_complex "[1:a]asplit=2[sc][mix];[0:a][sc]sidechaincompress[compr];[compr][mix]amerge"
ffmpeg -i silence.mp3 -af silencedetect=noise=0.0001 -f null -
ffmpeg -f lavfi -i flite=text='So fare thee well, poor devil of a Sub-Sub, whose commentator I am':voice=slt
ffmpeg -i input.png -vf chromakey=green out.png
ffmpeg -f lavfi -i color=c=black:s=1280x720 -i video.mp4 -shortest -filter_complex "[1:v]chromakey=0x70de77:0.1:0.2[ckout];[0:v][ckout]overlay[out]" -map "[out]" output.mkv
ffmpeg -i input.png -vf colorkey=green out.png
ffmpeg -i background.png -i video.mp4 -filter_complex "[1:v]colorkey=0x3BBD1E:0.3:0.2[ckout];[0:v][ckout]overlay[out]" -map "[out]" output.flv
ffmpeg -f lavfi -i nullsrc=s=100x100,coreimage=filter=CIQRCodeGenerator@inputMessage=https\\\\\://FFmpeg.org/@inputCorrectionLevel=H -frames:v 1 QRCode.png
ffmpeg -f lavfi -i color -vf curves=cross_process:plot=/tmp/curves.plt -frames:v 1 -f null -
ffmpeg -i INPUT -f lavfi -i nullsrc=s=hd720,lutrgb=128:128:128 -f lavfi -i nullsrc=s=hd720,geq='r=128+30*sin(2*PI*X/400+T):g=128+30*sin(2*PI*X/400+T):b=128+30*sin(2*PI*X/400+T)' -lavfi '[0][1][2]displace' OUTPUT
ffmpeg -i INPUT -f lavfi -i nullsrc=hd720,geq='r=128+80*(sin(sqrt((X-W/2)*(X-W/2)+(Y-H/2)*(Y-H/2))/220*2*PI+T)):g=128+80*(sin(sqrt((X-W/2)*(X-W/2)+(Y-H/2)*(Y-H/2))/220*2*PI+T)):b=128+80*(sin(sqrt((X-W/2)*(X-W/2)+(Y-H/2)*(Y-H/2))/220*2*PI+T))' -lavfi '[1]split[x][y],[0][x][y]displace' OUTPUT
ffmpeg -i video.avi -filter_complex 'extractplanes=y+u+v[y][u][v]' -map '[y]' y.avi -map '[u]' u.avi -map '[v]' v.avi
ffmpeg -i in.vob -vf "fieldorder=bff" out.dv
ffmpeg -i file.ts -vf find_rect=newref.pgm,cover_rect=cover.jpg:mode=cover new.mkv
ffmpeg -i file.ts -vf find_rect=newref.pgm,cover_rect=cover.jpg:mode=cover new.mkv
ffmpeg -i LEFT -i RIGHT -filter_complex framepack=frameseq OUTPUT
ffmpeg -i LEFT -i RIGHT -filter_complex [0:v]scale=w=iw/2[left],[1:v]scale=w=iw/2[right],[left][right]framepack=sbs OUTPUT
ffmpeg -f lavfi -i B<haldclutsrc>=8 -vf "hue=H=2*PI*t:s=sin(2*PI*t)+1, curves=cross_process" -t 10 -c:v ffv1 clut.nut
ffmpeg -f lavfi -i mandelbrot -i clut.nut -filter_complex '[0][1] haldclut' -t 20 mandelclut.mkv
ffmpeg -f lavfi -i B<haldclutsrc>=8 -vf "
ffmpeg -i in.avi -vf "hflip" out.avi
ffmpeg -i main.mpg -i ref.mpg -lavfi libvmaf -f null -
ffmpeg -i main.mpg -i ref.mpg -lavfi libvmaf="psnr=1:enable-transform=1" -f null -
ffmpeg -i input -i logo -filter_complex 'overlay=10:main_h-overlay_h-10' output
ffmpeg -i input -i logo1 -i logo2 -filter_complex 'overlay=x=10:y=H-h-10,overlay=x=W-w-10:y=H-h-10' output
ffmpeg -i left.avi -i right.avi -filter_complex "
ffmpeg -i test.avi -codec:v:0 wmv2 -ar 11025 -b:v 9000k
ffmpeg -i input.mkv -vf palettegen palette.png
ffmpeg -i input.mkv -i palette.png -lavfi paletteuse output.gif
ffmpeg -i input -vf pullup -r 24000/1001 ...
ffmpeg -i input.avi -filter:v 'readvitc,drawtext=fontfile=FreeMono.ttf:text=%{metadata\\:lavfi.readvitc.tc_str\\:--\\\\\\:--\\\\\\:--\\\\\\:--}:x=(w-tw)/2:y=400-ascent'
ffmpeg -i INPUT -vf "shuffleframes=0 2 1" OUTPUT
ffmpeg -i INPUT -vf "shuffleframes=9 1 2 3 4 5 6 7 8 0" OUTPUT
ffmpeg -i INPUT -vf shuffleplanes=0:2:1:3 OUTPUT
ffmpeg -i input.mkv -vf signature=filename=signature.bin -map 0:v -f null -
ffmpeg -i input1.mkv -i input2.mkv -filter_complex "[0:v][1:v] signature=nb_inputs=2:detectmode=full:format=xml:filename=signature%d.xml" -map :v -f null -
ffmpeg -i main.mpg -i ref.mpg -lavfi  "ssim;[0:v][1:v]psnr" -f null -
ffmpeg -i 320x240.avi -f lavfi -i color=gray -f lavfi -i color=black -f lavfi -i color=white -lavfi threshold output.avi
ffmpeg -i 320x240.avi -f lavfi -i color=gray -f lavfi -i color=white -f lavfi -i color=black -lavfi threshold output.avi
ffmpeg -i 320x240.avi -f lavfi -i color=gray -i 320x240.avi -f lavfi -i color=gray -lavfi threshold output.avi
ffmpeg -i 320x240.avi -f lavfi -i color=gray -f lavfi -i color=white -i 320x240.avi -lavfi threshold output.avi
ffmpeg -i 320x240.avi -f lavfi -i color=gray -i 320x240.avi -f lavfi -i color=white -lavfi threshold output.avi
ffmpeg -i in.avi -vf thumbnail,scale=300:200 -frames:v 1 out.png
ffmpeg -skip_frame nokey -i file.avi -vf 'scale=128:72,tile=8x8' -an -vsync 0 keyframes%03d.png
ffmpeg -i INPUT -vf zscale=transfer=linear,tonemap=clip,zscale=transfer=bt709,format=yuv420p OUTPUT
ffmpeg -i INPUT -vf trim=60:120
ffmpeg -i INPUT -vf trim=duration=1
ffmpeg -i input -vf vidstabdetect=shakiness=5:show=1 dummy.avi
ffmpeg -i inp.mpeg -vf vidstabtransform,unsharp=5:5:0.8:3:3:0.4 inp_stabilized.mpeg
ffmpeg -i in.avi -vf "vflip" out.avi
ffmpeg -i ref.mpg -lavfi vmafmotion -f null -
ffmpeg -f lavfi -i coreimagesrc=s=100x100:filter=CIQRCodeGenerator@inputMessage=https\\\\\://FFmpeg.org/@inputCorrectionLevel=H -frames:v 1 QRCode.png
ffmpeg -i opening.mkv -i episode.mkv -i ending.mkv -filter_complex \
ffmpeg -nostats -i input.mp3 -filter_complex ebur128 -f null -
ffmpeg -i bambi.avi -i pr0n.mkv -filter_complex "[0:v][1:v] interleave" out.avi
ffmpeg -i video.avi -vf select='gt(scene\,0.4)',scale=160:120,tile -frames:v 1 preview.png
ffmpeg -copyts -vsync 0 -segment_time_metadata 1 -i input.ffconcat -vf select=concatdec_select -af aselect=concatdec_select output.avi
ffmpeg -i audio.flac -lavfi showspectrumpic=s=1024x1024 spectrogram.png
ffmpeg -i audio.flac -lavfi showwavespic=split_channels=1:s=1024x800 waveform.png
ffmpeg -i input.flac -lavfi showspectrum=mode=separate:scale=log:overlap=0.875:color=channel:slide=fullframe:data=magnitude -an -c:v rawvideo magnitude.nut
ffmpeg -i input.flac -lavfi showspectrum=mode=separate:scale=lin:overlap=0.875:color=channel:slide=fullframe:data=phase -an -c:v rawvideo phase.nut
ffmpeg -i magnitude.nut -i phase.nut -lavfi spectrumsynth=channels=2:sample_rate=44100:win_func=hann:overlap=0.875:slide=fullframe output.flac
ffmpeg -i INPUT -filter_complex asplit=5 OUTPUT






--help full
--help decoder=
--help encoder=
--help demuxer=
--help muxer=
--help filter=
--help 
--help 
--help 
--help 
--help 
--help 
--help 
--help 
--help 

-codecs
-protocols
-layouts




-loglevel trace
debug
verbose
info






-report













-cryptokey         <binary>     .D...... decryption ke

-fdebug            <flags>      ED...... print specific debug info



crccheck                     .D...... verify embedded CRCs
     bitstream                    .D...... detect bitstream specification deviations





"-codec copy" or "-codec: copy" would copy all
       the streams without reencoding
























