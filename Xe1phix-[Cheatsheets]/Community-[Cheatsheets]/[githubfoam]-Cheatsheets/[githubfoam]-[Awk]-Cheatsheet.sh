----------------------------------------------------------------------------------------------------
NF is a predefined variable whose value is the number of fields in the current record
parse fields by field separator FS (default single space)
----------------------------------------------------------------------------------------------------
#string match,tab delimited file, starting with any of letter A,C,T,G ending with forward slash

$ cat test.txt
id1 342 C/T
id2 7453 T/A/-/G/C
id3 531 T/C
id4 756 A/T/G
id5 23 A/G
id6 717 T/A/C
id7 718 C/T/A
----------------------------------------------------------------------------------------------------
#string match,pattern containing forward slash

$ echo "///aaa"| awk '$0~v' v="//"
///aaa
$ echo "///aaa"|awk '/[/]/'
///aaa
----------------------------------------------------------------------------------------------------
#string match,Print lines where the third field is either snow or snowman

$ cat dummyfile
C1    C2    C3
1     a     snow
2     b     snowman
snow     c     sowman

$ awk '(index($3, "snow") != 0) {print}' dummyfile
1     a     snow
2     b     snowman
$ awk 'index($3, "snow")' dummyfile
1     a     snow
2     b     snowman
$ awk '($3=="snow" || $3=="snowman") {print}' dummyfile
1     a     snow
2     b     snowman
$ awk '$3 ~ /snow/ { print }' dummyfile
1     a     snow
2     b     snowman
$ awk '$3~/^snow(man)?$/' dummyfile
1     a     snow
2     b     snowman
$ awk '$3 ~ /snow|snowman/' dummyfile
1     a     snow
2     b     snowman

----------------------------------------------------------------------------------------------------
#string match, escaping reserved characters

awk '/search-pattern/ {print $1}'
echo "0xfffff8a000025010 0x000000011501c010 \REGISTRY\MACHINE\SYSTEM" | awk '/REGISTRY\\MACHINE\\SYSTEM/ {print $1 " " $3}'
----------------------------------------------------------------------------------------------------
#monitor root partition, string match

$ df -h | awk '$NF == "/"'
/dev/sda1        18G  7.7G  9.0G  47% /
$ df -h | awk '$NF == "/" { print "root partition / avail space..:",$4 }'
$ df -h | awk '$NF == "/" { print "root partition / use%..:",$5 }'
root partition / use%..: 15%
$ df -h | awk '$NF == "/" { print $5 }'|tail -1 |tr -d '%'
15

$ df -h | awk '{if( NR==1) print $0}'
Filesystem      Size  Used Avail Use% Mounted on
$ df -h | awk '$NF == "/" { print $4 }'
35G



$ free | awk '/Mem:/{printf("RAM Usage: %.2f%\n"), $3/$2*100}'
RAM Usage: 29.55%
$ free | awk '/Mem:/{printf("%.2f%\n"), $3/$2*100}'
29.52%
$ free | awk '/Mem:/{printf("%.2f%\n"), $3/$2*100}' | tail -1 |tr -d '%'
29.59

#arithmetic operation, truncating decimal
$ var=$(free | awk '/Mem:/{printf("%.2f%\n"), $3/$2*100}' | tail -1 |tr -d '%' | bc )
$ echo $var
29.05
$ echo ${var%.*}
29

#arithmetic operation, rounding percent
$ free | awk '/Mem:/{printf("%.2f%\n"), $3/$2*100}' | tail -1 |tr -d '%' | bc | xargs printf %.0f

$ echo "               total        used        free      shared  buff/cache   available" && free -h | awk '/Mem:/{print}'
$ echo "Filesystem      Size  Used Avail Use% Mounted on" && df -h | awk '$NF == "/"'
----------------------------------------------------------------------------------------------------
awk '{pattern + action}' {filenames} 

awk '/string1/ && /string2/' file #search two strings in one line
echo 'theatre' | awk '/the/ && /heat/'

#multiple strings
awk '/error|critical/failed/' /var/log/httpd/error_log
awk 'BEGIN{IGNORECASE=1} /error|critical/failed/' /var/log/messages #case sensitive
awk '/myPattern1/ && /myPattern2/' /path/to/file
awk '/word1.*word2/' input
awk '!/HTTP\/2.0/' /var/log/nginx/log #not matching i.e. show all line except HTTP/2.0 logs

awk '{ print }' /etc/passwd
awk '{ print "hiya" }' /etc/passwd
awk -F: '{if($3 >= 1000 && $3 < 2**16-2) print $1}' /etc/passwd #

awk -F: ' {OFS="----"} {print $1,$2,$3} ' /etc/passwd
awk '{x=x+$2} {print x}' inventory
awk -F: '{ print $1 }' /etc/passwd | sort
awk 'END {print "number of lines..:" NR}' /etc/passwd

ls -l  | awk '{ x += $5 }  ; END { print "total bytes: " x }' 
total bytes: 170830969
ls -l . | awk '{ x += $5 } ; END { print "total kilobytes: " (x +1023)/1024 }'
total kilobytes: 166828
ls -l . | awk '{ x += $5 } ; END { print "total megabytes: " ((x +1023)/1024)/1024 }'
total megabytes: 162.918
ls -l | awk ' $6 == "Nov" { sum += $5 } END { print "the total number of megabytes of files that were last modified in November..: "((x +1023)/1024)/1024  } '

$ Input_text=" Desiginning Website with CSS3 "
# Print the string after Removing the spaces from the beginning of the variable
$ echo "${Input_text}" | awk '{gsub(/^[ \t]+/,""); print $0, " JQuery" }'
# Print the string after Removing the spaces from the end of the variable
$ echo "${Input_text}" | awk '{gsub(/[ \t]+$/,""); print $0, " JQuery" }'
# Print the string after Removing the spaces from the beginning and end of the variable
$ echo "${Input_text}" | awk '{gsub(/^[ \t]+| [ \t]+$/,""); print $0, " JQuery" }'

#deletes leading and tailing spaces and squeezes to a single space every spaces between words
$ echo -e "   \t  A   \tB\tC   \t  " | awk '{$1=$1};1' 
awk '{$1=$1;print}' file.txt #remove all leading and trailing spaces and tabs from each line in an output
awk '{gsub(/[[:blank:]]/,""); print}' raw_file.txt | cat -n #Removing Horizontal Whitespace Only
awk -v ORS="" '{gsub(/[[:space:]]/,""); print}' raw_file.txt | cat -n #Removing All Whitespace Characters
----------------------------------------------------------------------------------------------------  
#Awk If Statement

$cat student-marks
Jones 2143 78 84 77
Gondrol 2321 56 58 45
RinRao 2122 38 37
Edwin 2537 87 97 95
Dayan 2415 30 47

$ awk '{
if ($3 =="" || $4 == "" || $5 == "")
	print "Some score for the student",$1,"is missing";'
}' student-marks

$ awk '{
if ($3 >=35 && $4 >= 35 && $5 >= 35)
	print $0,"=>","Pass";
else
	print $0,"=>","Fail";
}' student-marks

$ cat grade.awk
{
total=$3+$4+$5;
avg=total/3;
if ( avg >= 90 ) grade="A";
else if ( avg >= 80) grade ="B";
else if (avg >= 70) grade ="C";
else grade="D";

print $0,"=>",grade;
}

$ awk -f grade.awk student-marks
$ awk 'ORS=NR%3?",":"\n"' student-marks #Awk Ternary ( ?: ) 
----------------------------------------------------------------------------------------------------  