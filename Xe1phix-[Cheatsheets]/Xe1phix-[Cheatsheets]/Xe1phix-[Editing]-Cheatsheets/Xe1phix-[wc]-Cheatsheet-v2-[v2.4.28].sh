
wc -mlw file1.txt file2.txt #Count words, characters, and lines in multiple files 	
ls -l *.pdf | wc -l #Count a Certain Type of Files in a Directory
wc -m yourTextFile # count the total number of characters	
wc -w yourTextFile #count the number of words
$ wc -c file1.txt #the number of characters in a file
$ wc -l file1.txt #the number of lines in a file
$ head -5 .bash_history | wc -w # the number of words in the first 5 lines of the file

# filecount=$(ls | wc -l)
# echo $filecount
