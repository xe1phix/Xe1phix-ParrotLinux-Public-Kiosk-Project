#!/bin/sh


## Download all images from a 4chan thread
function 4get () { curl $1 | grep -i "File<a href" | awk -F '<a href="' '{print $4}' | awk -F '" ' '{print $1}' | xargs wget }




## Download all images from a 4chan thread
function 4chandl () { wget -e robots=off -nvcdp -t 0 -Hkrl 0 -I \*/src/ -P . "$1" }




## Download all images from a 4chan thread
curl -s $1 | grep -o -i '<a href="//images.4chan.org/[^>]*>' | sed -r 's%.*"//([^"]*)".*%\1%' | xargs wget





## Download all images on a 4chan thread
read -p "Please enter the 4chan url: "|egrep '//i.4cdn.org/[a-z0-9]+/src/([0-9]*).(jpg|png|gif)' - -o|nl -s https:|cut -c7-|uniq|wget -nc -i - --random-wait




## Download all images from a 4chan thread
curl -s http://boards.4chan.org/wg/|sed -r 's/.*href="([^"]*).*/\1\n/g'|grep images|xargs wget




## Download all images from a 4chan thread
curl -s http://boards.4chan.org/---/res/nnnnnn | grep -o -i 'File: <a href="//images.4chan.org\/[a-z]*\/src\/[0-9]*\.[a-z]\{3\}' | sed -r 's/File: <a href="\/\///' |xargs wget





## 4chan image batch downloader
## Replace thread_link with the link of the thread you want to download images of.
wget $thread_link -qO - | sed 's/\ /\n/g' | grep -e png -e jpg | grep href | sed 's/href\=\"/http:/g' | sed 's/"//g' | uniq | xargs wget







wget -nd -r -l 1 -A jpg,png,jpeg  https://8ch.net/CHANNAME/res/THREAD_NAME.html



## 4chan:
wget -P pictures -nd -r -l 1 -H -D i.4cdn.org -A png,gif,jpg,jpeg,webm [thread-url]


## 8chan:
wget -P pictures -nd -r -l 1 -H -D media.8ch.net -A png,gif,jpg,jpeg,webm [thread-url]



wget --show-progress -4 -P ~/Downloads/b/GIF/ -nd -r -l 1 -H -D i.4cdn.org -A gif,webm $URL

--convert-links
wget --show-progress -4 -P ~/Downloads/b/ -nd -r -l 1 -H -D i.4cdn.org -A gif,webm $URL

wget --show-progress -4 -P ~/Downloads/b/ -nd -r -l 1 -H -D i.4cdn.org -A gif,webm https://boards.4chan.org/gif/thread/14411531


wget --show-progress -4 -P ~/Downloads/b/ -nd -r -l 1 -H -D i.4cdn.org -A gif,webm https://boards.4chan.org/gif/thread/14407074

wget --show-progress -4 -P ~/Downloads/b/ -nd -r -l 1 -H -D i.4cdn.org -A gif,webm https://boards.4chan.org/gif/thread/14372026



wget --show-progress -4 -P ~/Downloads/b/ -nd -r -l 1 -H -D i.4cdn.org -A png,gif,jpg,jpeg,webm https://boards.4chan.org/b/thread/791783658
