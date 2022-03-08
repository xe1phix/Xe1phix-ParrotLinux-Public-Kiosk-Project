#!/usr/bin/env bash
## Check builds with: shellcheck -e SC2004,SH2086 <scriptname>
## Turn off history for Bash
set +o history
## Assign name of this script and file path to variables for latter use
Var_script_dir="${0%/*}"
Var_script_name="${0##*/}"

## Notes on steghide options used
### Info and checking options
##  info or --info
##    Display info about cover or stego file
##  encinfo or --encinfo
##    Display list of encryption alogrithms and modes that can be used
##  
### Embeding options
##  -ef or --embedfile <file-name>
##    File that will be embeded into image or audio
##  -cf or --coverfile <file-name>
##    File that will be used for embeding data into; image or audio
##  -sf or --stegofile <file-name>
##    File that will be made from the previous two files data
##  -Z or --dontcompress
##    Turn off Steghide compression
##  -K or --nochecksum
##    Turn off Steghide checksum writing (saves 32 bits)
##  -N or --dontembedname
##    Turn off Steghide embeding of file name meta-data into resulting file
### Extracting options
##  -sf or --stegofile <file-name>
##    File that contains embeded data and image or audio data; resulting file
##    from above steps with the same option.
##  -xf or --extractfile <file-name>
##    Create file name (ignoring any embeded file names) from data embeded within
##    image or audio
### Extra options
##   -p or --passsphase <passphrase-string>
##    Automate passphrase prompting for steghide; not recomended
### Supported image or audio file types
##  Images: JPEG, BMP
##  Audio: WAV, AU

Func_rotate_with_steghide(){
	_old_pwd="${PWD}"
	_input_file_path="${1}"
	_steghide_auto_pass_length=""
	_steghide_cover_dir=""
	_steghide_pass_path=""
	## Build array if non-exsistant of acceptable file types for steghide
	if [ -d "${_steghide_cover_dir}" ] && [ "${#_arr_cover_list[@]}" = "0" ]; then
		find "${_steghide_cover_dir}" -xtype f | while read _path; do
			case "${_path##*.}" in
				au|AU|bmp|BMP|jpeg|JPEG|wav|WAV)
					declare -ag "_arr_cover_list+=( ${_path} )"
				;;
			esac
		done
		## Bail if no array was built
		if [ "${#_arr_cover_list[@]}" = "0" ]; then
			exit 1
		fi
	fi
	## Export steghide counter for keeping track of array index
	export _steghide_counter="${_steghide_counter:-0}"
	## Do something fancy here...
##	_auto_passphrase="$(base64 /dev/urandom | tr -cd '[:print:]' | head -c${_steghide_auto_pass_length})"
##	"${_steghide_pass_path}"
	
	## Export index count plus one for next time this function is called
	export _steghide_counter="$((${_steghide_counter}+1))"
	
	_steghide_output_dir=""
	_steghide_enc_options="--ef ${_input_file_path}"
	_steghide_dec_options=""
	_output_file_path="${_input_file_path##*/}/${_steghide_output_dir}"
	
	
	
}

## Turn on history for Bash
set +o history
