* an information gathering tool designed for extracting metadata of public documents (pdf,doc,xls,ppt,docx,pptx,xlsx) belonging to a target company
* perform a search in Google to identify and download the documents to local disk and then will extract the metadata with different libraries like Hachoir, PdfMiner? and others
* with the results it will generate a report with usernames, software versions, and servers or machine names that will help Penetration testers in the information gathering phase
* Helpful Google Doc: [metagoofil](https://docs.google.com/document/d/1pJ_2EzVwYsManMDPdf51jLZ4pbaqCtpINurKTLRdXIo/edit)

### Common Commands
* Help
  * "metagoofil -h"
* Extract public pdf, doc, and ppt files from target.com (limited to 200 searches and 5 downloads), save the downloads to "/root/Desktop/metagoofil/" and output results to "/root/Desktop/metagoofil/result.html"
  * “metagoofil -d target.com -t pdf,doc,ppt -l 200 -n 5 -o /root/Desktop/metagoofil/ -f /root/Desktop/metagoofil/result.html
* Scan for documents from a domain (-d kali.org) that are PDF files (-t pdf), searching 100 results (-l 100), download 25 files (-n 25), saving the downloads to a directory (-o kalipdf), and saving the output to a file (-f kalipdf.html)
  * metagoofil -d kali.org -t pdf -l 100 -n 25 -o kalipdf -f kalipdf.html

### Optional
* W3M allows you to view the output HTML file within the terminal
  * "apt-get install w3m"
  * View the original output file in terminal "w3m /root/Desktop/metagoofil/result.html"
