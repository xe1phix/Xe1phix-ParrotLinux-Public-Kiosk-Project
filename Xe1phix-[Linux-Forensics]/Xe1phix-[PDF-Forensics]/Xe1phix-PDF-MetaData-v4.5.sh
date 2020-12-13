#!/bin/bash

## read tags from the original PDF
exiftool -all:all $FILE

## remove tags (XMP + metadata) from the PDF
exiftool -all:all= $FILE

## linearize the file to remove orphan data
qpdf --linearize $FILE

## read XMP from the modified PDF
exiftool -all:all $FILE

## read all strings from the modified PDF
cat $FILE | strings > $FILE.txt

## read XMP from embedded objects in the modified PDF
exiftool -extractEmbedded -all:all $FILE





hachoir-subfile



pdfxray_lite -f file.pdf -r rpt_



##-====================================================================-##
##   [+] pdfextract - Extract various data from the PDF, such as: 
##       streams, scripts, image, fonts, metadata, attachments, etc.
##-====================================================================-##
pdfextract file.pdf




## ---------------------------------------------------------------------------------------- ##
##   [?] Peepdf will point out suspicious objects that are often used for attacks. 
## ---------------------------------------------------------------------------------------- ##
##   [?] object 13 contains JavaScript 
## ---------------------------------------------------------------------------------------- ##


##-============================================-##
##   [+] Enter its interactive console type:
##-============================================-##
peepdf -i $File.pdf


## ----------------------------------------------------------------------------------------------- ##
##   [?] Typing “object 13” will show the object’s contents, including the embedded JavaScript.
## ----------------------------------------------------------------------------------------------- ##
##   [?] Peepdf will automatically decode the contents of the stream 
##       that includes JavaScript using the appropriate filters.
## ----------------------------------------------------------------------------------------------- ##
peepdf -i file.pdf








# merge all pdf files from a directory to a single pdf file
pdftk *.pdf cat output out.pdf

# reverse page order of a pdf file
PDFTK_PAGES=$(pdftk in.pdf dump_data | grep NumberOfPages | sed "s/^.*: //")
pdftk in.pdf cat $PDFTK_PAGES-1 output out.pdf

# Strip metadata in pdf
PDFTK_FILE=in.pdf
pdftk $PDFTK_FILE dump_data | sed -e 's/\(InfoValue:\)\s.*/\1\ /g' | pdftk $PDFTK_FILE update_info - output out.pdf


# The following commands will modify the orientation of the PDF file
# Supposing you have a normal PDF these commands will:

pdftk in.pdf cat 1east output out.pdf # Rotate the first PDF page 90 degrees clockwise
pdftk in.pdf cat 1west output out.pdf # Rotate the first PDF page 90 degrees counterclockwise
pdftk in.pdf cat 1south output out.pdf # Rotate the first PDF page 180 dedgrees

# Print a single page or a range of pages to the output file
pdftk in.pdf cat 3-5 output out.pdf # Page range
pdftk in.pdf cat 2 output out.pdf # Single range

# Merge various PDF files
pdftk in1.pdf in2.pdf in3.pdf cat output out.pdf


clean_pdf() {
 pdftk $1 dump_data | \
  sed -e 's/\(InfoValue:\)\s.*/\1\ /g' | \
  pdftk $1 update_info - output clean-$1

 exiftool -all:all= clean-$1
 exiftool -all:all clean-$1
 exiftool -extractEmbedded -all:all clean-$1
 qpdf --linearize clean-$1 clean2-$1

 pdftk clean2-$1 dump_data
 exiftool clean2-$1
 pdfinfo -meta clean2-$1
}







clean_pdf() {
    FILE=$1
    FILE="${FILE%%.*}"
    echo "#############"
    echo $1
    echo "#############"
    if [ -e $1 ]
        then
        pdftk $1 dump_data | \
        sed -e 's/\(InfoValue:\)\s.*/\1\ /g' | \
        pdftk $1 update_info - output ${FILE}.clean.pdf
        exiftool -all:all= ${FILE}.clean.pdf
        exiftool -all:all ${FILE}.clean.pdf
        exiftool -extractEmbedded -all:all ${FILE}.clean.pdf
        qpdf --linearize ${FILE}.clean.pdf ${FILE}.clean2.pdf
        pdftk ${FILE}.clean2.pdf1 dump_data
        exiftool ${FILE}.clean2.pdf
        echo "#############"
        echo "Metadata of file "${FILE}.clean2.pdf
        pdfinfo -meta ${FILE}.clean2.pdf
        echo "#############"
    else
        echo "File not found!"

        fi
}





clean_pdf() {
    FILE=$1
    FILE="${FILE%%.*}"
    echo "#############"
    echo $1
    echo "#############"
    if [ -e $1 ]
        then
        pdftk $1 dump_data | \
        sed -e 's/\(InfoValue:\)\s.*/\1\ /g' | \
        pdftk $1 update_info - output ${FILE}.clean.pdf
        exiftool -all:all= ${FILE}.clean.pdf
        exiftool -all:all ${FILE}.clean.pdf
        exiftool -extractEmbedded -all:all ${FILE}.clean.pdf
        qpdf --linearize ${FILE}.clean.pdf ${FILE}.clean2.pdf
        pdftk ${FILE}.clean2.pdf dump_data
        exiftool ${FILE}.clean2.pdf
        echo "#############"
        echo "Metadatos de fichero "${FILE}.clean2.pdf
        pdfinfo -meta ${FILE}.clean2.pdf
        echo "#############"
    else
        echo "File not found!"

        fi
}




pdftk %s update_info %s output %s
pdftk %s dump_data





pdf-redact-tools --explode example_document.pdf
pdf-redact-tools --merge example_document.pdf
pdf-redact-tools --sanitize untrusted.pdf


mktemp --tmpdir 

qvm-convert-pdf test.pdf


convert -size ${IMG_WIDTH}x${IMG_HEIGHT} -depth ${IMG_DEPTH} rgb:$RGB_FILE pdf:$PDF_FILE 

convert page.rgb page.pdf
    




case $type in    # input mimetype is supported
        "pdf")
		pdftk $input dump_data | sed -e 's/\(InfoValue:\)\s.*/\1\ /g' | pdftk $input update_info - output $input.clean.pdf
		exiftool -all:all= $input.clean.pdf
		exiftool -all:all $input.clean.pdf
		exiftool -extractEmbedded -all:all $input.clean.pdf
		qpdf --linearize $input.clean.pdf $output.pdf
		pdftk $output.pdf dump_data
		exiftool $output.pdf
		rm -f $input.clean.pdf_original
		rm -f $input.clean.pdf
		mv $output.pdf $output
		;;
        *) ((mime_error++)); mime_error_file="$mime_error_file \"$input_filename\"" ;;
    esac
done




xmessage "$1" -timeout 5
notify-send "$1"
{ echo "message:$1" | zenity --notification --listen & }
{ kdialog --title "$1" --passivepopup "This popup will disappear in 5 seconds" 5 & }













