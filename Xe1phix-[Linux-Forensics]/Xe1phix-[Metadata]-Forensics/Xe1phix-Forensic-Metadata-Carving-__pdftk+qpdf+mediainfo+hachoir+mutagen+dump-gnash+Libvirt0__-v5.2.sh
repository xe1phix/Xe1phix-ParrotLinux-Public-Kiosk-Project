pkexec pngmeta -h


hachoir-metadata
--verbose 
--log=
--debug
--profiler
--parser-list
--bench
--level=9
--raw
--type
--mime



hachoir-metadata --verbose --debug 13925274_1728279320760456_5106983712270762423_n.jpg
[warn] Skip IPTC key 103: 2MOP5-hLbeUMhN0o0Lqh
[warn] Skip IPTC key 40: FBMD01000ab6030000390e00004d2600006f260000ce260000535e0000bd8d00007b9000009d900000d690000097d30000


Display information about a video file
mediainfo foo.mkv


Display aspect ratio
mediainfo --Inform="Video;%DisplayAspectRatio%" foo.mkv
mediainfo --Inform="Video;file://Video.txt" foo.mkv


--Info-Parameters
--Inform
--LogFile=

--Output=XML
--Full

--Help-AnOption
--Help-Inform
--Help-Output

Display mediatrace info
--Details=1

--Language=raw
                    Display non-translated unique identifiers


exiftool -tagsfromfile @ -iptc:all -codedcharacterset=utf8 a.jpg


These unknown tags are not extracted unless the Unknown (-u) option is used.

ExtractEmbedded (-ee) option may be used to extract information from these embedded images

-U



## information may be removed permanently using the "qpdf" utility
qpdf --linearize in.pdf out.pdf"




Write a report on PDF document metadata and bookmarks to report.txt
         pdftk in.pdf dump_data output report.txt

Decrypt a PDF
         pdftk secured.pdf input_pw foopass output unsecured.pdf

encrypt_128bit

       Encrypt a PDF using 128-bit strength (the default), withhold all permissions (the default)
         pdftk 1.pdf output 1.128.pdf owner_pw foopass

       Same as above, except password 'baz' must also be used to open output PDF
         pdftk 1.pdf output 1.128.pdf owner_pw foo user_pw baz

       Join in1.pdf and in2.pdf into a new PDF, out1.pdf
         pdftk in1.pdf in2.pdf cat output out1.pdf
         or (using handles):
         pdftk A=in1.pdf B=in2.pdf cat A B output out1.pdf
         or (using wildcards):
         pdftk *.pdf cat output combined.pdf

Uncompress PDF page streams for editing the PDF in a text editor (e.g., vim, emacs)
         pdftk doc.pdf output doc.unc.pdf uncompress

       Repair a PDF's corrupted XREF table and stream lengths, if possible
         pdftk broken.pdf output fixed.pdf

       Burst a single PDF document into pages and dump its data to doc_data.txt
         pdftk in.pdf burst

       Burst a single PDF document into encrypted pages. Allow low-quality printing
         pdftk in.pdf burst owner_pw foopass


Copies all of the attachments from the input PDF into the current folder or to an output directory
pdftk report.pdf unpack_files output ~/atts/

Packs arbitrary files into a PDF using PDF's file attachment features.
pdftk in.pdf attach_files table1.html table2.html to_page 6 output out.pdf



verbose
drop_xfa
drop_xmp
owner_pw
user_pw
dump_data_utf8
dump_data_fields
dump_data_annots
update_info


pdftk in.pdf update_info in.info output out.pdf






Check metadata structures of a JPEG file, only report errors
pecomato check file.jpg
            
            
              
--list
check
dump-full
dump-value

--extract



--fix

--log-level






--check-linearization     check file integrity and linearization status
--show-linearization      check and show all linearization data
--show-xref               show the contents of the cross-reference table
--show-object=obj[,gen]   show the contents of the given object
  --raw-stream-data       show raw stream data instead of object contents
  --filtered-stream-data  show filtered stream data instead of object contents
--show-npages             print the number of pages in the file
--show-pages              shows the object/generation number for each page
  --with-images           also shows the object IDs for images on each page
--check                   check file structure + encryption, linearization


--show-encryption

--encrypt
--decrypt
--password=
--encryption-file-password=

key-length may be 40, 128, or 256

 --encrypt user-password owner-password key-length flags --

--extract=[yn]           allow other text/graphic extraction
    --print=print-opt        control printing access
    --modify=modify-opt      control modify access
        modify-opt may be:

      all                   allow full document modification
      annotate              allow comment authoring and form operations
      form                  allow form field fill-in and signing
      assembly              allow document assembly only
      none                  allow no modifications

    --cleartext-metadata     prevents encryption of metadata
    --use-aes=[yn]           indicates whether to use AES encryption
    --force-V4               forces use of V=4 encryption handler



--stream-data=compress


pdfinfo
-meta
-js
-struct-text
pdfinfo -listenc

mutagen-inspect el79.mp3





yelp ghelp:gpdftext

pdfchain


pdfsig


metaflac

--list --data-format=text
--list --application-data-format=hexdump

--show-tag=
--show-vendor-tag
--show-bps
--show-md5sum
--export-tags-to=-
--remove-all-tags





--explain
--no-keep-foreign-metadata
--analyze









dump-gnash
--audio-dump


wav2swf
swfstrings
swfextract
swfdump
gif2swf



evince



extract metadata from a file:

tracker extract --verbosity=debug /path/to/some/file.mp3

Kaa Metadata media info
menuexec "mminfo -h"

iinfo
iconvert
idiff
igrep
iv

## iinfo (print detailed info about images), 

## iconvert (convert among formats, data types, or modify metadata), 

## idiff (compare images),

## igrep (search images for matching metadata).


## mminfo - Kaa Metadata media info.
mminfo -d 2 



--epub-metadata


dnswalk
dnsmap
dnsrecon
dnstracer
dnschef
dnsspoof


wifiarp
wifi-honey 
wifitap
xprobe2
darkstat




mmls
mmcat
mmstat
mactime-sleuthkit
affcat
jls
istat
img_stat
img_cat
ils-sleuthkit
ifind
icat
fsstat
foremost
fls
fimap
ewfinfo
ewfacquire
ewfacquirestream
ewfexport
ewfverify
volafox
volatility
yara
autopsy

openvas-check-setup
openvas-feed-update
gsd
openvas-setup
openvas-start


owasp-mantra-ff
thunderbird
claws-mail 


atk6-passive_discovery6 
atk6-kill_router6 
atk6-parasite6 
theharvester

stegosuite
sysprof



pdfid -h

pdf-parser
peepdf


eeprom.py -R RFIDIOt.rfidiot.READER_ACG -l /dev/ttyUSB0 -s 9600 

rtlsdr-scanner
siparmyknife
voiphopper

sandi-gui


socat
/usr/share/airgeddon/airgeddon.sh


us -h


virtualbricks
virt-manager
aqemu


yubikey-personalization-gui





pandoc -s -o output.html input.txt

## To produce an HTML/javascript slide show
pandoc -t FORMAT -s habits.txt -o habits.html


## To produce a PDF slide show using beamer, type
pandoc -t beamer habits.txt -o habits.pdf


## pandoc concatenates input files, and keep the metadata in a YAML file and pass it to pandoc
pandoc chap1.md chap2.md chap3.md metadata.yaml -s -o book.html


pandoc -o hello.tex hello.txt

iconv -t utf-8 input.txt | pandoc | iconv -f utf-8


## To produce a PDF, specify an output file with a .pdf extension. 
pandoc test.txt -o test.pdf

## Generate a bash completion script.  To enable bash completion with pandoc, add this to your .bashrc:
eval "$(pandoc --bash-completion)"


--metadata=

--extract-media=
--smart






--data-dir=

--from=
rst
latex
json
docbook
docx
epub
html
odt

--output=
zimwiki
pdf
asciidoc
odt

--standalone

--trace
--dump-args
--verbose





meta-json

















## Analyses and repairs cache metadata on logical volume /dev/vg/metadata:
cache_check /dev/vg/metadata

## Dumps the cache metadata on logical volume /dev/vg/metadata to standard output in XML format:
cache_dump /dev/vg/metadata

## Dumps the cache metadata on logical volume /dev/vg/metadata whilst repairing it to standard output in XML format:
cache_dump --repair /dev/vg/metadata

## Reads  the binary cache metadata from file metadata, repairs it and writes it to logical volume /dev/vg/metadata for further
## processing by the respective device-mapper target:

cache_repair -i metadata -o /dev/vg/metadata

## Restores  the XML formatted cache metadata on file metadata to logical volume /dev/vg/metadata for further processing by the
## respective device-mapper target:

cache_restore -i metadata -o /dev/vg/metadata



cache_metadata_size --nr-blocks 10240
cache_metadata_size --block-size 128 --device-size 1024000




geotifcp -h
tiffcp
listgeo
applygeo


applygeo file.geo file.tiff

https://trac.osgeo.org/geotiff/


/usr/libexec/xt_geoip/xt_geoip_dl


Shell commands to build the databases and put them to where they are expected:
xt_geoip_build -D /usr/share/xt_geoip



GeoTiffDirectory, GeoTiffDoubleParams and GeoTiffAsciiParams
tags: GPSLatitude, GPSLatitudeRef,
       GPSLongitude, GPSLongitudeRef, and GPSAltitude and GPSAltitudeRef






aqemu
kvm
qemu-system
qemu-img

qemu-io
qemu-make-debian-root
qemu-system-x86_64
qemu-x86_64
qemu-user
qemu-tilegx
vdeq
perf_4.9-kvm
vmware-checkvm

virt-convert
virt-xml

virsh




## -------------------------------------------------- ##
##   Create a 10G qcow2 disk image and attach it to
##   to 'fedora18' for the next VM startup:
## -------------------------------------------------- ##
virt-xml fedora18 --add-device --disk /var/lib/libvirt/images/newimage.qcow2,format=qcow2,size=10



## ----------------------------------------------------------- ##
##    list of all suboptions that --disk and --network take
## ----------------------------------------------------------- ##
virt-xml --disk=? --network=?


readonly


## ----------------------------------------------------------- ##
##   Enable the boot device menu for domain 'EXAMPLE':
## ----------------------------------------------------------- ##
virt-xml EXAMPLE --edit --boot menu=on




## ----------------------------------------------------------- ##
##   Change disk 'hda' IO to native and use startup policy as 'optional'.
## ----------------------------------------------------------- ##
virt-xml fedora20 --edit target=hda --disk io=native,startup_policy=optional



## ----------------------------------------------------------- ##
##   Change all host devices to use driver_name=vfio for VM 'fedora20' on the remote connection
## ----------------------------------------------------------- ##
virt-xml --connect qemu+ssh://remotehost/system fedora20 --edit all --hostdev driver_name=vfio



## ----------------------------------------------------------- ##
##   Hotplug host USB device 001.003 to running domain 'fedora19':
## ----------------------------------------------------------- ##
virt-xml fedora19 --update --add-device --hostdev 001.003



## ----------------------------------------------------------- ##
##   Hot unplug the disk vdb from the running domain 'rhel7':
## ----------------------------------------------------------- ##
virt-xml rhel7 --update --remove-device --disk target=vdb


## ----------------------------------------------------------- ##
##   Generate XML for a virtio console device and print it to stdout:
## ----------------------------------------------------------- ##
virt-xml --build-xml --console pty,target_type=virtio








virt-install --connect qemu:///system --virt-type kvm --name Parro--memory 500 --disk size=10 --cdrom /dev/cdrom --os-variant 




virt-install \
              --connect qemu:///system \
              --virt-type kvm \
              --name Parrot
              --memory 500 \
              --disk size=10 \
              --cdrom /dev/cdrom \
              --os-variant 













http://www.pdflabs.com/tools/pdftk-the-pdf-toolkit/
www.pdftk.com
http://www.iptc.org/IIM/
http://owl.phy.queensu.ca/~phil/exiftool/struct.html#Serialize
http://www.exif.org/specifications.html
http://www.iptc.org/IPTC4XMP/
http://www.w3.org/TR/rdf-syntax-grammar/
http://www.metadataworkinggroup.org/
http://www.cipa.jp/std/documents/e/DC-008-Translation-2016-E.pdf
http://www.iptc.org/std/IIM/4.1/specification/IIMV4.1.pdf
http://owl.phy.queensu.ca/~phil/exiftool/struct.html
http://www.optimasc.com/products/fileid/
http://www.iptc.org/IPTC4XMP/
http://www.color.org/icc_specs2.xalter
http://www.cipa.jp/std/documents/e/DC-010-2012_E.pdf
http://www.cipa.jp/std/documents/e/DC-010-2012_E.pdf
http://www.fastpictureviewer.com/help/#rtfcomments
https://developers.google.com/depthmap-metadata/
https://developers.google.com/panorama/metadata/
https://github.com/google/spatial-media/blob/master/docs/spherical-video-rfc.md
http://www.prismstandard.org/
http://www.cipa.jp/std/documents/e/DC-010-2012_E.pdf
http://www.w3.org/TR/SVG11/
http://www.remotesensing.org/geotiff/spec/geotiffhome.html
http://www.charttiff.com/whitepapers.shtml
http://ns.useplus.org/ldf/vocab/
http://ns.useplus.org/
http://www.adobe.com/devnet-apps/photoshop/fileformatashtml/
http://u88.n24.queensu.ca/exiftool/forum/index.php?topic=4898.msg23972#msg23972
http://www.adobe.com/products/dng/
https://www.w3.org/Graphics/JPEG/jfif3.pdf
http://graphcomp.com/info/specs/livepicture/fpx.pdf
http://www.cipa.jp/std/documents/e/DC-007_E.pdf
http://www.cipa.jp/std/documents/e/DC-006_E.pdf
http://www.scalado.com/
https://github.com/gopro/gpmf-parser
http://web.archive.org/web/20080828211305/http://www.tocarte.com/media/axs_afcp_spec.pdf
http://rs.tdwg.org/dwc/index.htm
http://owl.phy.queensu.ca/~phil/exiftool/MIE1.1-20070121.pdf
http://www.w3.org/Graphics/GIF/spec-gif89a.txt
http://bellard.org/bpg/
http://www.libpng.org/pub/png/spec/1.2/
https://wiki.mozilla.org/APNG_Specification
http://www.ietf.org/rfc/rfc3066.txt
http://flif.info/
http://www.djvu.org/
http://www.openexr.com/
http://www.libpgf.org/
http://www.graphics.cornell.edu/online/formats/rgbe/
http://radsite.lbl.gov/radiance/refer/filefmts.pdf
http://www.adobe.com/devnet/pdf/pdf_reference.html
http://www.id3.org/
http://www.loc.gov/standards/iso639-2/php/code_list.php
http://www.xiph.org/vorbis/doc/
http://www.xiph.org/vorbis/doc/
https://www.opus-codec.org/docs/
http://developer.apple.com/mac/library/documentation/QuickTime/QTFF/QTFFChap1/qtff1.html
https://github.com/google/spatial-media/blob/master/docs/spherical-video-v2-rfc.md
http://www.matroska.org/technical/specs/index.html
https://github.com/google/spatial-media/blob/master/docs/spherical-video-v2-rfc.md
https://developers.google.com/speed/webp/docs/riff_container
http://tech.ebu.ch/docs/tech/tech3285.pdf
https://tech.ebu.ch/docs/tech/tech3306-2009.pdf
http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/AIFF/AIFF.html
https://wiki.theory.org/BitTorrentSpecification
http://medical.nema.org/
http://tools.ietf.org/html/rfc6350
http://www.microsoft.com/en-ca/download/details.aspx?id=10725
http://www.mollux.org/projects/pecomato/
https://github.com/quodlibet/mutagen


