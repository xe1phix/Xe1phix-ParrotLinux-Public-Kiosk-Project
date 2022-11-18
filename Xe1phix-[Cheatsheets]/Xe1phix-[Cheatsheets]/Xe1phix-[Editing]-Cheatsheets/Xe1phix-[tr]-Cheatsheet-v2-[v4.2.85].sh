echo BigcapsSmallCaps | tr [:lower:] [:upper:] # convert string into lower case, capital case etc
tr '()' '[]' -> In a given fragment of text, replace all parentheses with box brackets 
tr -d [:lower:] -> In a given fragment of text, delete all the lowercase characters
tr -d "[:space:]" < raw_file.txt #remove all whitespace characters from the file
echo -e "   \t  A   \tB\tC   \t  " | tr -d "[:blank:]" #deletes any space or tabulation character
tr -s  ' ' -> In a given fragment of text, replace all sequences of multiple spaces with just one space
distribution=$(lsb_release --id | cut -f2 | tr [:upper:] [:lower:]) #all big caps to small caps
