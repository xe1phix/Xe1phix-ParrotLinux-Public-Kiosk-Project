#!/bin/sh
#
# Bourne script by Josh L Glenn (hexcode@riseup.net)
# Strips EXIF metadata info from files in folder $HOME/Pictures
#
#
# This is the default location where photos are stored in GNU/Linux
# i.e Ubuntu/Debian generally most people save to home dir/Pictures
#
# if you have not done so already before using this script you need to run:
# sudo apt-get install mogrify
mogrify -strip $HOME/Pictures/*.jpg
mogrify -strip $HOME/Pictures/*.jpeg
mogrify -strip $HOME/Pictures/*.png
mogrify -strip $HOME/Pictures/*.gif
