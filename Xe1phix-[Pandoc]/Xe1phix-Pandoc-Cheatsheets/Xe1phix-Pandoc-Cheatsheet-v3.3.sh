#!/bin/sh
##-=========================================-##
##   [+] Xe1phix-Pandoc-Cheatsheet-v3.2.sh
##-=========================================-##


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "      [+] Generate a bash completion script:      "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
eval "$(pandoc --bash-completion)"



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] HTML fragment:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc MANUAL.txt -o example1.html

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Standalone HTML file:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s MANUAL.txt -o example2.html

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] HTML with table of contents, CSS, and custom footer:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s --toc -c pandoc.css -A footer.html MANUAL.txt -o example3.html

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "                  [+] LaTeX:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s MANUAL.txt -o example4.tex

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "        [+] From LaTeX to markdown:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s example4.tex -o example5.text

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "           [+] reStructuredText:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s -t rst --toc MANUAL.txt -o example6.text

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "        [+] Rich text format (RTF):"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s MANUAL.txt -o example7.rtf

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "         [+] Beamer slide show:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -t beamer SLIDES -o example8.pdf

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "             [+] DocBook XML:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s -t docbook MANUAL.txt -o example9.db

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "               [+] Man page:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s -t man pandoc.1.md -o example10.1

echo "##-=-=-=-=-=-=-=-=-=-##"
echo "    [+] ConTeXt:"
echo "##-=-=-=-=-=-=-=-=-=-##"
pandoc -s -t context MANUAL.txt -o example11.tex

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "     [+] Converting a web page to markdown:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s -r html http://www.gnu.org/software/make/ -o example12.text

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "          [+] From markdown to PDF:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc MANUAL.txt --pdf-engine=xelatex -o example13.pdf

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] PDF with numbered sections and a custom LaTeX header:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -N --template=mytemplate.tex --variable mainfont="Palatino" --variable sansfont="Helvetica" --variable monofont="Menlo" --variable fontsize=12pt --variable version=2.0 MANUAL.txt --pdf-engine=xelatex --toc -o example14.pdf

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] A wiki program using Happstack and pandoc:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "             [+] HTML slide shows:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s --mathml -i -t dzslides SLIDES -o example16a.html
pandoc -s --webtex -i -t slidy SLIDES -o example16b.html
pandoc -s --mathjax -i -t revealjs SLIDES -o example16d.html


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] TeX math in HTML:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc math.text -s -o mathDefault.html
pandoc math.text -s --mathml  -o mathMathML.html
pandoc math.text -s --webtex  -o mathWebTeX.html
pandoc math.text -s --mathjax -o mathMathJax.html
pandoc math.text -s --katex   -o mathKaTeX.html

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Syntax highlighting of delimited code blocks:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc code.text -s --highlight-style pygments -o example18a.html
pandoc code.text -s --highlight-style kate -o example18b.html
pandoc code.text -s --highlight-style monochrome -o example18c.html
pandoc code.text -s --highlight-style espresso -o example18d.html
pandoc code.text -s --highlight-style haddock -o example18e.html
pandoc code.text -s --highlight-style tango -o example18f.html
pandoc code.text -s --highlight-style zenburn -o example18g.html

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] GNU Texinfo, converted to info, HTML, and PDF formats:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc MANUAL.txt -s -o example19.texi
makeinfo --no-validate --force example19.texi -o example19.info
makeinfo --no-validate --force example19.texi --html -o example19
texi2pdf example19.texi  # produces example19.pdf

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "          [+] OpenDocument XML:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc MANUAL.txt -s -t opendocument -o example20.xml

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] ODT (OpenDocument Text, readable by OpenOffice):"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc MANUAL.txt -o example21.odt

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] MediaWiki markup:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s -t mediawiki --toc MANUAL.txt -o example22.wiki

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] EPUB ebook:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc MANUAL.txt -o MANUAL.epub

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Markdown citations:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s --bibliography biblio.bib --filter pandoc-citeproc CITATIONS -o example24a.html
pandoc -s --bibliography biblio.json --filter pandoc-citeproc --csl chicago-fullnote-bibliography.csl CITATIONS -o example24b.html
pandoc -s --bibliography biblio.yaml --filter pandoc-citeproc --csl ieee.csl CITATIONS -t man -o example24c.1


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Textile writer:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s MANUAL.txt -t textile -o example25.textile


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Textile reader:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s example25.textile -f textile -t html -o example26.html


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Org-mode:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s MANUAL.txt -o example27.org


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] AsciiDoc:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s MANUAL.txt -t asciidoc -o example28.txt


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Word docx:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s MANUAL.txt -o example29.docx


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] LaTeX math to docx:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s math.tex -o example30.docx


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] DocBook to markdown:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -f docbook -t markdown -s howto.xml -o example31.text


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] MediaWiki to html5:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -f mediawiki -t html5 -s haskell.wiki -o example32.html


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Custom writer:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -t sample.lua example33.text -o example33.html


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Docx with a reference docx:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc --reference-doc twocolumns.docx -o UsersGuide.docx MANUAL.txt


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Docx to markdown, including math:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s example30.docx -t markdown -o example35.md


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] EPUB to plain text:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc MANUAL.epub -t plain -o example36.text



--verbose 
--log=










echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert HTML --> TEXT:         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s -o output.html input.txt


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert hello.txt from:"
echo "         Markdown --> LaTeX                            "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -f markdown -t latex hello.txt



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert hello.html from        "
echo "         HTML --> Markdown:            "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -f html -t markdown hello.html





curl -H "Content-Type: text/{{inputFormat}}" -X POST -d "%DATA%" http://pandoc-as-a-service.com/{{outputFormat}}




## EPUB Metadata
--epub-metadata






## With these custom styles, you can use your input document as a reference-doc
pandoc test/docx/custom-style-reference.docx -f docx+styles -t markdown




## Create A .EPUB Out of A Text File:
pandoc mybook.txt -o mybook.epub


## run pandoc to make the ebook, 
## using The Text File As Our title page. 
## And The Markdown Files Are The Chapters.
pandoc -o progit.epub title.txt \
  01-introduction/01-chapter1.markdown \
  02-git-basics/01-chapter2.markdown \
  03-git-branching/01-chapter3.markdown \
  04-git-server/01-chapter4.markdown \
  05-distributed-git/01-chapter5.markdown \
  06-git-tools/01-chapter6.markdown \
  07-customizing-git/01-chapter7.markdown \
  08-git-and-other-scms/01-chapter8.markdown \
  09-git-internals/01-chapter9.markdown



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert from HTML to markdown:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -f html -t markdown




echo "##-==================================================================-##"
echo "## ------------------------------------------------------------------ ##"
echo "    [?] The filename test1.md tells pandoc which file to convert. "
echo "    [?] The -s option says to create a “standalone” file."
echo "        with a header and footer, not just a fragment. "
echo "    [?] And the -o test1.html says to put the output "
echo "        in the file test1.html."
echo "## ------------------------------------------------------------------ ##"
echo "##-==================================================================-##"
pandoc test1.md -f markdown -t html -s -o test1.html




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "     [+] create a LaTeX document:        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc test1.md -f markdown -t latex -s -o test1.tex



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert A Markdown Document To PDF:        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -o test.pdf test.markdown.




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert A Whole Directory of files from Markdown to RTF        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
for f in *.txt; do pandoc "$f" -s -o "${f%.txt}.rtf"; done





echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Ask pandoc to write-out the default template for markdown:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc --print-default-template=markdown > template.markdown




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Create 5 copies of the input audio with ffmpeg:      "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
ffmpeg -i INPUT -filter_complex asplit=5 OUTPUT





pandoc -o output.html input.txt
pandoc -s -o output.html input.txt
pandoc -f markdown -t latex hello.txt
pandoc -f html -t markdown hello.html
pandoc --list-input-formats
pandoc --list-output-formats
pandoc -o hello.tex hello.txt
pandoc -f html -t markdown http://www.fsf.org
pandoc -f html -t markdown --request-header User-Agent:"Mozilla/5.0" \
eval "$(pandoc --bash-completion)"
pandoc --filter ./caps.py -t latex
pandoc -t json | ./caps.py latex | pandoc -f json -t latex
pandoc --print-default-data-file=abbreviations
pandoc --print-default-data-file refer‐
pandoc -s --gladtex input.md -o myfile.htex
pandoc --ignore-args -o foo.html -s foo.txt -- -e latin1
pandoc -o foo.html -s
pandoc -D *FORMAT*
pandoc -f html-native_divs-native_spans -t markdown
pandoc -f markdown+lhs -t html
pandoc -f markdown+lhs -t html+lhs
pandoc --list-highlight-languages
pandoc --list-output-formats
pandoc --filter pandoc-citeproc myinput.txt
pandoc -t FORMAT -s habits.txt -o habits.html
pandoc -t beamer habits.txt -o habits.pdf
pandoc -t beamer habits.txt -V theme:Warsaw -o habits.pdf
pandoc --list-highlight-languages
pandoc --list-highlight-styles
pandoc -t data/sample.lua
pandoc --print-default-data-file sample.lua

















## 


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert .txt File Into A .tex File:      "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -o hello.tex hello.txt




pandoc --list-input-formats
pandoc --list-output-formats 
pandoc --list-extensions


echo "##-=-=-`=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert The Files Character Encoding To UTF-8:       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
iconv -t utf-8 input.txt | pandoc | iconv -f utf-8



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert Text File --> PDF File:      "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc test.txt -o test.pdf




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Pandoc will Fetch The Content Using HTTP:        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -f html -t markdown http://www.fsf.org



## custom User-Agent string 
or another Secified Header when requesting a document from a URL:
pandoc -f html -t markdown --request-header User-Agent:"Mozilla/5.0" http://www.fsf.org



## 


## 


## Extract images and other media contained in or linked from the source document to the path DIR
--extract-media=




## 
pandoc test/docx/custom-style-reference.docx -f docx+styles -t markdown


## 
pandoc test/docx/custom-style-reference.docx -f docx -t markdown













