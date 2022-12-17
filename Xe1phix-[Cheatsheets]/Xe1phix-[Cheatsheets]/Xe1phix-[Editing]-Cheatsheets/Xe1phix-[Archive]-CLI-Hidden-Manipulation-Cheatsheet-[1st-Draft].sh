apt-secure Archive::Zip Archive::Zip::FAQ funzip gpg-zip tarcat







engrampa -h matelivecd.iso
           Extract matelivecd.iso to ./matelivecd in the current working directory.


engrampa ./matelivecd/* -a matelivecd.tar.gz
           Create a new gzip compressed tarball archive named matelivecd.tar.gz, containing all the files located in
           the ./matelivecd directory.

       engrampa matelivecd.tar.gz
           Open matelivecd.tar.gz to view and manipulate its contents.



--add-to=ARCHIVE
--add
--extract-to=FOLDER
--extract
--extract-here
--default-dir=
--force

designed to prevent two possible attacks



--info

-extract-to=

--extract

--multi-extract

--compress=


--add










ziptool
ziptool -n           Create archive
ziptool -c           Check zip archive consistency when opening it
ziptool -n           Create archive if it doesn't exist.








Encryption Methods


AES-256



ziptool stat index  Print information about archive entry index.


ziptool set_file_encryption $Variable

ziptool set_file_encryption index
ziptool set_file_encryption method
ziptool set_file_encryption password

                 Set file encryption method for archive entry index to method with password password.



ziptool set_file_mtime index
ziptool set_file_mtime timestamp

                 Set file modification time for archive entry index to UNIX mtime timestamp.

ziptool set_file_mtime_all timestamp
                 Set file modification time for all archive entries to UNIX mtime timestamp.

ziptool set_password password
                 Set default password for encryption/decryption to password.


ziptool set_file_compression index method compression_flags
                 Set file compression method for archive entry index to method using compression_flags.  Note: Cur‐
                 rently, compression_flags are ignored.


ziptool replace_file_contents index data
                 Replace file contents for archive entry index with the string data.


ziptool get_num_entries flags
                 Print number of entries in archive using flags.

ziptool name_locate name flags
                 Find entry in archive with the filename name using flags and print its index.


ziptool get_extra index extra_index flags
                 Print extra field extra_index for archive entry index using flags.

ziptool get_extra_by_id index extra_id extra_index flags
                 Print extra field extra_index of type extra_id for archive entry index using flags.

ziptool add name content
                 Add file called name using the string content from the command line as data.

ziptool add_dir name
                 Add directory name.

ziptool add_file name file_to_add offset len
                 Add file name to archive, using len bytes from the file file_to_add as input data, starting at
                 offset.

ziptool add_from_zip name archivename index offset len
                 Add file called name to archive using data from another zip archive archivename using the entry
                 with index index and reading len bytes from offset.

ziptool cat index   Output file contents for entry index to stdout.


ziptool stat index  Print information about archive entry index









get the full, short-format listing

setenv ZIPINFO --t
zipinfo -t storage            [only totals line]
zipinfo -st storage           [full listing]


long-format listing (not verbose), including header and totals lines


zipinfo -l storage




list the complete contents of the archive without header and totals lines



zipinfo --h-t storage
zipinfo storage \*


setenv ZIPINFO --t
zipinfo storage








see the most recently modified files in the archive

zipinfo -T storage | sort -nr -k 7 | sed 15q



get  maximal  information  about the ZIP archive

zipinfo -v storage | more



list information on a single file within the archive, in medium format, specify the filename explicitly:

       zipinfo -m storage unshrink.c







Image::ExifTool
Image::ExifTool::TagNames





























