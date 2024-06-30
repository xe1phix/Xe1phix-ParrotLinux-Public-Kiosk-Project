# FFmpeg cheat sheet

A list of useful commands for the ffmpeg command line tool.

Download FFmpeg: https://www.ffmpeg.org/download.html

Full documentation: https://www.ffmpeg.org/ffmpeg.html

## Basic conversion

````
ffmpeg -i in.mp4 out.avi
````

### Remux an MKV file into MP4

````
ffmpeg -i in.mkv -c:v copy -c:a copy out.mp4
````

### High-quality encoding

Use the `crf` (Constant Rate Factor) parameter to control the output quality. The lower crf, the higher the quality (range: 0-51). The default value is 23, and visually lossless compression corresponds to `-crf 18`. Use the `preset` parameter to control the speed of the compression process. Additional info: https://trac.ffmpeg.org/wiki/Encode/H.264

````
ffmpeg -i in.mp4 -preset slower -crf 18 out.mp4
````

## Trimming

Without re-encoding:
````
ffmpeg -ss [start] -i in.mp4 -t [duration] -c copy out.mp4
````
- [`-ss`](http://ffmpeg.org/ffmpeg-all.html#Main-options) specifies the start time, e.g. `00:01:23.000` or `83` (in seconds)
- [`-t`](http://ffmpeg.org/ffmpeg-all.html#Main-options) specifies the duration of the clip (same format).
- Recent `ffmpeg` also has a flag to supply the end time with `-to`.
- [`-c`](http://ffmpeg.org/ffmpeg-all.html#Main-options) copy copies the first video, audio, and subtitle bitstream from the input to the output file without re-encoding them. This won't harm the quality and make the command run within seconds.

With re-encoding:

If you leave out the `-c copy` option, `ffmpeg` will automatically re-encode the output video and audio according to the format you chose. For high quality video and audio, read the [x264 Encoding Guide](https://ffmpeg.org/trac/ffmpeg/wiki/x264EncodingGuide) and the [AAC Encoding Guide](http://ffmpeg.org/trac/ffmpeg/wiki/AACEncodingGuide), respectively.

For example:
````
ffmpeg -ss [start] -i in.mp4 -t [duration] -c:v libx264 -c:a aac -strict experimental -b:a 128k out.mp4
````

## Mux video and audio from another video

To copy the video from in0.mp4 and audio from in1.mp4:
````
ffmpeg -i in0.mp4 -i in1.mp4 -c copy -map 0:0 -map 1:1 -shortest out.mp4
````
- With [-c copy](http://ffmpeg.org/ffmpeg.html#Stream-copy) the streams will be `stream copied`, not re-encoded, so there will be no quality loss. If you want to re-encode, see [FFmpeg Wiki: H.264 Encoding Guide](https://trac.ffmpeg.org/wiki/Encode/H.264).
- The `-shortest` option will cause the output duration to match the duration of the shortest input stream.
- See the [`-map` option documentation](http://ffmpeg.org/ffmpeg.html#Advanced-options) for more info.


## Concat demuxer

First, make a text file.
````
file 'in1.mp4'
file 'in2.mp4'
file 'in3.mp4'
file 'in4.mp4'
````
Then, run `ffmpeg`:
````
ffmpeg -f concat -i list.txt -c copy out.mp4
````

## Delay audio/video

Delay video by 3.84 seconds:
````
ffmpeg -i in.mp4 -itsoffset 3.84 -i in.mp4 -map 1:v -map 0:a -vcodec copy -acodec copy out.mp4
````
Delay audio by 3.84 seconds:
````
ffmpeg -i in.mp4 -itsoffset 3.84 -i in.mp4 -map 0:v -map 1:a -vcodec copy -acodec copy out.mp4
````

## Burn subtitles

Use the [libass](http://ffmpeg.org/ffmpeg.html#ass) library (make sure your ffmpeg install has the library in the configuration `--enable-libass`).

First convert the subtitles to .ass format:
````
ffmpeg -i sub.srt sub.ass
````
Then add them using a video filter:

````
ffmpeg -i in.mp4 -vf ass=sub.ass out.mp4
````

## Extract the frames from a video

To extract all frames from between 1 and 5 seconds, and also between 11 and 15 seconds:

````
ffmpeg -i in.mp4 -vf select='between(t,1,5)+between(t,11,15)' -vsync 0 out%d.png
````

To extract one frame per second only:

````
ffmpeg -i in.mp4 -fps=1 -vsync 0 out%d.png
````

## Rotate a video

Rotate 90 clockwise:

````
ffmpeg -i in.mov -vf "transpose=1" out.mov
````

For the transpose parameter you can pass:

````
0 = 90CounterCLockwise and Vertical Flip (default)
1 = 90Clockwise
2 = 90CounterClockwise
3 = 90Clockwise and Vertical Flip
````

Use `-vf "transpose=2,transpose=2"` for 180 degrees.

## Download "Transport Stream" video streams

1. Locate the playlist file, e.g. using Chrome > F12 > Network > Filter: m3u8
2. Download and concatenate the video fragments:

````
ffmpeg -i "path_to_playlist.m3u8" -c copy -bsf:a aac_adtstoasc out.mp4
````

If you get a "Protocol 'https not on whitelist 'file,crypto'!" error, add the `protocol_whitelist` option:

````
ffmpeg -protocol_whitelist "file,http,https,tcp,tls" -i "path_to_playlist.m3u8" -c copy -bsf:a aac_adtstoasc out.mp4
````

## Mute some of the audio

To replace the first 90 seconds of audio with silence:

````
ffmpeg -i in.mp4 -vcodec copy -af "volume=enable='lte(t,90)':volume=0" out.mp4
````

To replace all audio between 1'20" and 1'30" with silence:

````
ffmpeg -i in.mp4 -vcodec copy -af "volume=enable='between(t,80,90)':volume=0" out.mp4
````

## Deinterlace

Deinterlacing using "yet another deinterlacing filter".

````
ffmpeg -i in.mp4 -vf yadif out.mp4
````

## Create a video slideshow from images

Parameters: `-r` marks the image framerate (inverse time of each image); `-vf fps=25` marks the true framerate of the output.

````
ffmpeg -r 1/5 -i img%03d.png -c:v libx264 -vf fps=25 -pix_fmt yuv420p out.mp4
````

## Extract images from a video

- Extract all frames: `ffmpeg -i input.mp4 thumb%04d.jpg -hide_banner`
- Extract a frame each second: `ffmpeg -i input.mp4 -vf fps=1 thumb%04d.jpg -hide_banner`
- Extract only one frame: `ffmpeg -i input.mp4 -ss 00:00:10.000 -vframes 1 thumb.jpg`

## Metadata: Change the title

````
ffmpeg -i in.mp4 -map_metadata -1 -metadata title="My Title" -c:v copy -c:a copy out.mp4
````
