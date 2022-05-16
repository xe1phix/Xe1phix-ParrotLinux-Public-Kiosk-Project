# Remove all the sound related kernel modules
lsmod | grep snd | awk '{print $1}' | sudo xargs rmmod

# Find the ISPs of everyone who logged into your server
grep -o -E "Accepted publickey for .*" /var/log/auth.log | awk '{print $6}' | xargs -n1 whois | grep org-name

# Download all the Zed Shaw sessions and play them one after another
curl -s zedshaw.com/sessions/ | grep -o -P "http://zedshaw.music.s3.amazonaws.com/.*?.ogg" | xargs curl -s | ogg123 -

# Download all the Zed Shaw sessions, 6 *concurrently at a time* and play them *concurrently* creating a crazy mashup
curl -s zedshaw.com/sessions/ | grep -o -P "http://zedshaw.music.s3.amazonaws.com/.*?.ogg" | xargs -P 6 -n 1 curl -s | ogg123 -
