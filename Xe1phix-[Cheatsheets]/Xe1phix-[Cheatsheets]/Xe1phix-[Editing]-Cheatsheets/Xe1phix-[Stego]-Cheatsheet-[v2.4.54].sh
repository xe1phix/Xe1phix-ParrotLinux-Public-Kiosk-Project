






## embed the file secret.txt in the cover file picture.jpg.
steghide embed -cf picture.jpg -ef secret.txt


steghide extract -sf picture.jpg


steghide info 





## To embed the message hidden.txt into the monkey.jpg image:
outguess -k "my secret pass phrase" -d hidden.txt monkey.jpg out.jpg

## And in the other direction:
outguess -k "my secret pass phrase" -r out.jpg message.txt


## will retrieve the hidden message from the image.
## If you want to embed a second message, use:
outguess -k "secret1" -d hide1.txt -E -K "secret2" -D hide2.txt monkey.jpg out.jpg


## Outguess will first embed hide1.txt and then hide2.txt on top of it, using  error  correcting  codes.  
## The  second  messagehide2.txt can be retrieved with
outguess -k "secret2" -e -r out.jpg message.txt






## conceal the message "I am lying" in the file infile, with compression, and encrypted with the
## password "hello world". The resulting text will be stored in outfile.
stegsnow -C -m "I am lying" -p "hello world" infile outfile


## To extract the message, the command would be
stegsnow -C -p "hello world" outfile


## Note that the resulting message will not be terminated by a newline.
## To prevent line wrap if text with concealed whitespace is likely to be indented by mail or news readers, a line length of 72
## or less can be used.
stegsnow -C -l 72 -m "I am lying" infile outfile


## The approximate storage capacity of a file can be determined with the -S option.
stegsnow -S -l 72 infile




## conceal the message "Meet me at 6" in the file infile.gif, with compression, and encrypted with
## the password "hello world". The resulting text will be stored in outfile.gif.
gifshuffle -C -m "Meet me at 6" -p "hello world" infile.gif outfile.gif


## To extract the message, the command would be
gifshuffle -C -p "hello world" outfile.gif


## Note that the resulting message will not be terminated by a newline.
## The storage capacity of a file can be determined with the -S option.
gifshuffle -S infile.gif




