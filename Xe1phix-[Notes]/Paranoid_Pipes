#!/usr/bin/env bash
## Check builds with: shellcheck -e SC2004,SH2086 <scriptname>
set +o history
## Assign name of this script and file path to variables for latter use
Var_script_dir="${0%/*}"
Var_script_name="${0##*/}"
Var_script_description='maker of named pipe parsing template Bash scripts for GnuPG.'
Var_debug_level="0"
Var_log_level="0"
Var_script_log_path="${PWD}/${Var_script_name%.sh*}.log"
Var_columns="${COLUMNS:-$(tput cols)}"
Var_columns="${Var_columns:-80}"
Var_authors_contact='strangerthanbland@gmail.com'
Var_authors_name='S0AndS0'
Var_save_variables_yn="no"
Var_source_var_file=""
Var_script_version_main="2"
Var_script_version_sub="0"
Var_script_version_full="${Var_script_version_main}.${Var_script_version_sub}"
## Assigne executable paths as variables
Var_dev_null="/dev/null"
Var_echo="$(which echo)"
Var_chmod="$(which chmod)"
Var_chown="$(which chown)"
Var_mkfifo="$(which mkfifo)"
Var_mv="$(which mv)"
Var_rm="$(which rm)"
Var_tar="$(which tar)"
Var_cat="$(which cat)"
Var_gpg="$(which gpg)"
Var_mkdir="$(which mkdir)"
Var_touch="$(which touch)"
## Variables for encryption script copy
Var_enc_copy_save_yn="no"
Var_enc_copy_save_path="${PWD}/Encrypter.sh"
Var_enc_copy_save_ownership="$(id -un):$(id -gn)"
Var_enc_copy_save_permissions="750"
## Variables for encryption processes
Var_enc_yn="no"
Var_enc_gpg_opts="--always-trust --armor --batch --no-tty --encrypt"
Var_enc_parsing_bulk_out_dir="${PWD}/Bulk_Encrypted"
Var_enc_parsing_bulk_output_suffix=".gpg"
Var_enc_parsing_disown_yn="yes"
Var_enc_parsing_filter_input_yn="no"
Var_enc_parsing_filter_comment_pattern='\#*'
Var_enc_parsing_filter_allowed_chars='[^a-zA-Z0-9 _.@!#%&:;$\/\^\-\"\(\)\{\}\\]'
Var_enc_parsing_recipient="$(id -un)@${HOSTNAME}.local"
Var_enc_parsing_output_file="${PWD}/Encrypted_Results.gpg"
Var_enc_parsing_output_rotate_yn="yes"
Var_enc_parsing_output_rotate_actions="compress-encrypt,remove-old"
Var_enc_parsing_output_rotate_recipient="$(id -un)@${HOSTNAME}.local"
Var_enc_parsing_output_max_size="4096"
Var_enc_parsing_output_check_frequency="100"
Var_enc_parsing_save_output_yn="yes"
Var_enc_parsing_quit_string="quit"
Var_enc_pipe_file="${PWD}/Encryption_Named.pipe"
Var_enc_pipe_ownership="$(id -un):$(id -gn)"
Var_enc_pipe_permissions="600"
Var_enc_parsing_output_permissions="640"
Var_enc_parsing_output_ownership="$(id -un):$(id -gn)"
## Decryption variables
Var_dec_yn="no"
Var_dec_copy_save_yn="no"
Var_dec_copy_save_path="${PWD}/Decrypter.sh"
Var_enc_copy_save_ownership="$(id -un):$(id -gn)"
Var_enc_copy_save_permissions="750"
Var_dec_gpg_opts="--quiet --no-tty --always-trust --passphrase-fd 9 --decrypt"
Var_dec_parsing_bulk_out_dir="${PWD}/Bulk_Decrypted"
Var_dec_parsing_disown_yn="no"
Var_dec_parsing_save_output_yn="yes"
Var_dec_parsing_output_file="${PWD}/Decrypted_Results.txt"
Var_dec_pass=""
## Special variables
Var_dec_pipe_make_yn="no"
Var_dec_pipe_file="${PWD}/Decryption_Named.pipe"
Var_dec_pipe_permissions="600"
Var_dec_pipe_ownership="$(id -un):$(id -gn)"
Var_dec_parsing_quit_string="quit"
Var_dec_search_string=""
Var_dec_bulk_check_count_max="0"
Var_dec_bulk_check_sleep="120"
${Var_echo} "### ... Starting [${Var_script_name}] at $(date) ... ###"
## Wrap up function operations inside bellow function
Func_main(){
	_input=( "$@" )
	if [ "${#_input[@]}" = "0" ]; then
		Func_message "# Func_main running: Func_check_args \"--help\"" '1' '2'
		Func_check_args "--help"
	else
		Func_message "# Func_main running: Func_check_args \"${_input[*]}\"" '1' '2'
		Func_check_args "${_input[@]}"
		## Functions for encryption
		case "${Var_enc_yn}" in
			Y|y|Yes|yes|YES)
				Func_message "# Func_main running: Func_enc_main" '1' '2'
				Func_enc_main
			;;
			*)
				Func_message "# Func_main skipping: Func_enc_main" '1' '2'
			;;
		esac
		## Functions for decryption
		case "${Var_dec_yn}" in
			Y|y|Yes|yes|YES)
				Func_message "# Func_main running: Func_dec_main" '1' '2'
				Func_dec_main
			;;
			*)
				Func_message "# Func_main skipping: Func_dec_main" '1' '2'
			;;
		esac
	fi
	unset -v _input[@]
}
Func_enc_main(){
	case "${Var_enc_copy_save_yn}" in
		Y|y|Yes|yes|YES)
			Func_message "# Func_enc_main running: Func_enc_write_script_copy" '2' '3'
			Func_enc_write_script_copy
			if [ -e "${Var_enc_copy_save_path}" ]; then
				Func_message "# Func_enc_main running: ${Var_enc_copy_save_path}" '2' '3'
				${Var_enc_copy_save_path}
			else
				Func_message "# Func_enc_main could not exicute: ${Var_enc_copy_save_path}" '2' '3'
				${Var_cat} "${Var_enc_copy_save_path}"
			fi
		;;
		*)
			Func_message "# Func_enc_main running: Func_enc_make_named_pipe" '2' '3'
			Func_enc_make_named_pipe
			case "${Var_enc_parsing_disown_yn}" in
				Y|y|Yes|yes|YES)
					Func_message "## \${Var_script_name} will differ cleanup trap assignment until reading from named pipe [\${Var_enc_pipe_file}] has finished..." '2' '3'
					Func_message "# Func_enc_main running: Func_enc_pipe_parser_loop >\"${Var_dev_null}\" 2>&1 &" '2' '3'
					Func_enc_pipe_parser_loop >"${Var_dev_null}" 2>&1 &
					PID_loop=$!
					disown "${PID_loop}"
					Func_message "# Func_enc_main disowned PID ${PID_loop} parsing loops" '2' '3'
				;;
				*)
					Func_message "## \${Var_script_name} will set exit trap now." '2' '3'
					trap '${Var_rm} "\${Var_enc_pipe_file}"' EXIT
					Func_message "# Func_enc_main running: Func_enc_pipe_parser_loop" '2' '3'
					Func_enc_pipe_parser_loop
					Func_message "# Func_enc_main quitting: Func_enc_pipe_parser_loop" '2' '3'
					set -o history
				;;
			esac
		;;
	esac
	if [ "${#Arr_extra_input[@]}" != "0" ] && [ -p "${Var_enc_pipe_file}" ]; then
		Func_message "# Func_enc_main writing extra input [\${#Arr_extra_input[@]}] to [${Var_enc_pipe_file}]" '2' '3'
		${Var_cat} <<<"${Arr_extra_input[*]}" > "${Var_enc_pipe_file}"
	fi
	Func_message "# Func_enc_main exiting encryption checks with: [$?]" '2' '3'
}
Func_dec_main(){
	case "${Var_dec_copy_save_yn}" in
		Y|y|Yes|yes|YES)
			Func_message "# Func_dec_main running: Func_dec_write_script_copy" '2' '3'
			Func_dec_write_script_copy
			if [ -e "${Var_dec_copy_save_path}" ]; then
				Func_message "# Func_dec_main running: ${Var_dec_copy_save_path}" '2' '3'
				${Var_dec_copy_save_path}
			else
				Func_message "# Func_dec_main could not exicute: ${Var_dec_copy_save_path}" '2' '3'
				${Var_cat} "${Var_dec_copy_save_path}"
			fi
		;;
		*)
			case "${Var_dec_pipe_make_yn}" in
				y|Y|yes|Yes)
					Func_message "# Func_dec_main running: Func_dec_make_named_pipe" '2' '3'
					Func_dec_make_named_pipe
				;;
			esac
			case "${Var_dec_parsing_save_output_yn}" in
				y|Y|yes|Yes)
					if ! [ -f "${Var_dec_parsing_output_file}" ]; then
						${Var_touch} "${Var_dec_parsing_output_file}"
						${Var_chmod} 660 "${Var_dec_parsing_output_file}"
					fi
				;;
			esac
			case "${Var_dec_parsing_disown_yn}" in
				Y|y|Yes|yes|YES)
					Func_message "# Func_dec_main running: Func_dec_watch_file >\"${Var_dev_null}\" 2>&1 &" '2' '3'
					Func_dec_watch_file >"${Var_dev_null}" 2>&1 &
					PID_loop=$!
					disown "${PID_loop}"
					Func_message "# Func_dec_main disowned PID ${PID_loop} parsing loops" '2' '3'
					Func_message "# Func_dec_main running: Func_dec_watch_bulk_dir >\"${Var_dev_null}\" 2>&1 &" '2' '3'
					Func_dec_watch_bulk_dir >"${Var_dev_null}" 2>&1 &
					PID_loop=$!
					disown "${PID_loop}"
					Func_message "# Func_dec_main disowned PID ${PID_loop} parsing loops" '2' '3'
				;;
				*)
					Func_message "# Func_dec_main running: Func_dec_watch_file" '2' '3'
					Func_dec_watch_file
					Func_message "# Func_dec_main running: Func_dec_watch_bulk_dir" '2' '3'
					Func_dec_watch_bulk_dir
				;;
			esac
			Func_message "# Func_dec_main exiting decryption checks with: [$?]" '2' '3'
		;;
	esac
	if [ "${#Arr_extra_input[@]}" != "0" ] && [ -p "${Var_dec_pipe_file}" ]; then
		Func_message "# Func_enc_main writing extra input [\${#Arr_extra_input[@]}] to [${Var_dec_pipe_file}]" '2' '3'
		${Var_cat} <<<"${Arr_extra_input[*]}" > "${Var_dec_pipe_file}"
	fi
}
Func_check_args(){
	_arr_input=( "${@}" )
	Func_message "# ${Var_script_name} parsing: ${_arr_input[*]}" '2' '3'
	let _arr_count=0
	until [ "${#_arr_input[@]}" = "${_arr_count}" ]; do
		_arg="${_arr_input[${_arr_count}]}"
		case "${_arg%=*}" in
			--debug-level|Var_debug_level)
				Func_assign_arg "Var_debug_level" "${_arg#*=}"
			;;
			--log-level|Var_log_level)
				Func_assign_arg "Var_log_level" "${_arg#*=}"
			;;
			--script-log-path|Var_script_log_path)
				Func_assign_arg "Var_script_log_path" "${_arg#*=}"
			;;
			--columns|Var_columns)
				Func_assign_arg "Var_columns" "${_arg#*=}"
			;;
			--dec-yn|Var_dec_yn)
				Func_assign_arg "Var_dec_yn" "${_arg#*=}"
			;;
			--dec-copy-save-yn|Var_dec_copy_save_yn)
				Func_assign_arg "Var_dec_copy_save_yn" "${_arg#*=}"
			;;
			--dec-copy-save-path|Var_dec_copy_save_path)
				Func_assign_arg "Var_dec_copy_save_path" "${_arg#*=}"
			;;
			--dec-copy-save-ownership|Var_dec_copy_save_ownership)
				Func_assign_arg "Var_dec_copy_save_ownership" "${_arg#*=}"
			;;
			--dec-copy-save-permissions|Var_dec_copy_save_permissions)
				Func_assign_arg "Var_dec_copy_save_permissions" "${_arg#*=}"
			;;
			--dec-bulk-check-count-max|Var_dec_bulk_check_count_max)
				Func_assign_arg "Var_dec_bulk_check_count_max" "${_arg#*=}"
			;;
			--dec-bulk-check-sleep|Var_dec_bulk_check_sleep)
				Func_assign_arg "Var_dec_bulk_check_sleep" "${_arg#*=}"
			;;
			--dec-gpg-opts|Var_dec_gpg_opts)
				Func_assign_arg "Var_dec_gpg_opts" "${_arg#*=}"
			;;
			--dec-pipe-make-yn|Var_dec_pipe_make_yn)
				Func_assign_arg "Var_dec_pipe_make_yn" "${_arg#*=}"
			;;
			--dec-pipe-file|Var_dec_pipe_file)
				Func_assign_arg "Var_dec_pipe_file" "${_arg#*=}"
			;;
			--dec-pipe-permissions|Var_dec_pipe_permissions)
				Func_assign_arg "Var_dec_pipe_permissions" "${_arg#*=}"
			;;
			--dec-pipe-ownership|Var_dec_pipe_ownership)
				Func_assign_arg "Var_dec_pipe_ownership" "${_arg#*=}"
			;;
			--dec-parsing-bulk-out-dir|Var_dec_parsing_bulk_out_dir)
				Func_assign_arg "Var_dec_parsing_bulk_out_dir" "${_arg#*=}"
			;;
			--dec-parsing-disown-yn|Var_dec_parsing_disown_yn)
				Func_assign_arg "Var_dec_parsing_disown_yn" "${_arg#*=}"
			;;
			--dec-parsing-save-output-yn|Var_dec_parsing_save_output_yn)
				Func_assign_arg "Var_dec_parsing_save_output_yn" "${_arg#*=}"
			;;
			--dec-parsing-output-file|Var_dec_parsing_output_file)
				Func_assign_arg "Var_dec_parsing_output_file" "${_arg#*=}"
			;;
			--dec-parsing-quit-string|Var_dec_parsing_quit_string)
				Func_assign_arg "Var_dec_parsing_quit_string" "${_arg#*=}"
			;;
			--dec-pass|Var_dec_pass)
				Func_assign_arg "Var_dec_pass" "${_arg#*=}"
			;;
			--dec-search-string|Var_dec_search_string)
				Func_assign_arg "Var_dec_search_string" "${_arg#*=}"
			;;
			--help|help)
				Func_message "# Func_check_args read variable [${_arg%=*}] with value [${_arg#*=}]" '2' '3'
				Func_help
				exit 0
			;;
			--license)
				Func_script_license_customizer
				exit 0
			;;
			--save-options-yn|Var_save_options_yn)
				Func_assign_arg "Var_save_options_yn" "${_arg#*=}"
			;;
			--save-variables-yn|Var_save_variables_yn)
				Func_assign_arg "Var_save_variables_yn" "${_arg#*=}"
			;;
			--source-var-file|Var_source_var_file)
				Func_assign_arg "Var_source_var_file" "${_arg#*=}"
				if [ -f "${Var_source_var_file}" ]; then
					Func_message "# Func_check_args running: source \"${Var_source_var_file}\"" '2' '3'
					source "${Var_source_var_file}"
				fi
			;;
			--enc-yn|Var_enc_yn)
				Func_assign_arg "Var_enc_yn" "${_arg#*=}"
			;;
			--enc-copy-save-yn|Var_enc_copy_save_yn)
				Func_assign_arg "Var_enc_copy_save_yn" "${_arg#*=}"
			;;
			--enc-copy-save-path|Var_enc_copy_save_path)
				Func_assign_arg "Var_enc_copy_save_path" "${_arg#*=}"
			;;
			--enc-copy-save-ownership|Var_enc_copy_save_ownership)
				Func_assign_arg "Var_enc_copy_save_ownership" "${_arg#*=}"
			;;
			--enc-copy-save-permissions|Var_enc_copy_save_permissions)
				Func_assign_arg "Var_enc_copy_save_permissions" "${_arg#*=}"
			;;
			--enc-gpg-opts|Var_enc_gpg_opts)
				Func_assign_arg "Var_enc_gpg_opts" "${_arg#*=}"
			;;
			--enc-parsing-bulk-out-dir|Var_enc_parsing_bulk_out_dir)
				Func_assign_arg "Var_enc_parsing_bulk_out_dir" "${_arg#*=}"
			;;
			--enc-parsing-bulk-output-suffix|Var_enc_parsing_bulk_output_suffix)
				Func_assign_arg "Var_enc_parsing_bulk_output_suffix" "${_arg#*=}"
			;;
			--enc-parsing-disown-yn|Var_enc_parsing_disown_yn)
				Func_assign_arg "Var_enc_parsing_disown_yn" "${_arg#*=}"
			;;
			--enc-parsing-filter-input-yn|Var_enc_parsing_filter_input_yn)
				Func_assign_arg "Var_enc_parsing_filter_input_yn" "${_arg#*=}"
			;;
			--enc-parsing-filter-comment-pattern|Var_enc_parsing_filter_comment_pattern)
				Func_assign_arg "Var_enc_parsing_filter_comment_pattern" "${_arg#*=}"
			;;
			--enc-parsing-filter-allowed-chars|Var_enc_parsing_filter_allowed_chars)
				Func_assign_arg "Var_enc_parsing_filter_allowed_chars" "${_arg#*=}"
			;;
			--enc-parsing-recipient|Var_enc_parsing_recipient)
				Func_assign_arg "Var_enc_parsing_recipient" "${_arg#*=}"
			;;
			--enc-parsing-output-file|Var_enc_parsing_output_file)
				Func_assign_arg "Var_enc_parsing_output_file" "${_arg#*=}"
			;;
			--enc-parsing-output-rotate-yn|Var_enc_parsing_output_rotate_yn)
				Func_assign_arg "Var_enc_parsing_output_rotate_yn" "${_arg#*=}"
			;;
			--enc-parsing-output-rotate-actions|Var_enc_parsing_output_rotate_actions)
				Func_assign_arg "Var_enc_parsing_output_rotate_actions" "${_arg#*=}"
			;;
			--enc-parsing-output-rotate-recipient|Var_enc_parsing_output_rotate_recipient)
				Func_assign_arg "Var_enc_parsing_output_rotate_recipient" "${_arg#*=}"
			;;
			--enc-parsing-output-max-size|Var_enc_parsing_output_max_size)
				Func_assign_arg "Var_enc_parsing_output_max_size" "${_arg#*=}"
			;;
			--enc-parsing-output-check-frequency|Var_enc_parsing_output_check_frequency)
				Func_assign_arg "Var_enc_parsing_output_check_frequency" "${_arg#*=}"
			;;
			--enc-parsing-output-permissions|Var_enc_parsing_output_permissions)
				Func_assign_arg "Var_enc_parsing_output_permissions" "${_arg#*=}"
			;;
			--enc-parsing-output-ownership|Var_enc_parsing_output_ownership)
				Func_assign_arg "Var_enc_parsing_output_ownership" "${_arg#*=}"
			;;
			--enc-parsing-save-output-yn|Var_enc_parsing_save_output_yn)
				Func_assign_arg "Var_enc_parsing_save_output_yn" "${_arg#*=}"
			;;
			--enc-parsing-quit-string|Var_enc_parsing_quit_string)
				Func_assign_arg "Var_enc_parsing_quit_string" "${_arg#*=}"
			;;
			--enc-pipe-permissions|Var_enc_pipe_permissions)
				Func_assign_arg "Var_enc_pipe_permissions" "${_arg#*=}"
			;;
			--enc-pipe-ownership|Var_enc_pipe_ownership)
				Func_assign_arg "Var_enc_pipe_ownership" "${_arg#*=}"
			;;
			--enc-pipe-file|Var_enc_pipe_file)
				Func_assign_arg "Var_enc_pipe_file" "${_arg#*=}"
			;;
			---*)
				_extra_var="${_arg%=*}"
				_extra_arg="${_arg#*=}"
				Func_assign_arg "${_extra_var/---/}" "${_extra_arg}"
			;;
			--version)
				${Var_echo} "# ${Var_script_name} version: ${Var_script_version_full}"
				exit 0
			;;
			*)
				Func_message "# Func_check_args running: declare -ag \"Arr_extra_input+=( \${_arg} )\"" '2' '3'
				declare -ag "Arr_extra_input+=( ${_arg} )"
			;;
		esac
		let _arr_count++
	done
	unset _arr_count
}
Func_help(){
	echo "# ${Var_script_dir}/${Var_script_name} knows the following command line options"
	echo "## Standard command line options"
	echo "# --columns				Var_columns=\"${Var_columns}\""
	echo "# --debug-level				Var_debug_level=\"${Var_debug_level}\""
	echo "# --log-level				Var_log_level=\"${Var_log_level}\""
	echo "# --script-log-path			Var_script_log_path=\"${Var_script_log_path}\""
	echo "# --save-variables-yn			Var_save_variables_yn=\"${Var_save_variables_yn}\""
	echo "# --source-var-file			Var_source_var_file=\"${Var_source_var_file}\""
	echo "# --license				Display the license for this script."
	echo "# --help				Display this message."
	echo "# --version				Display version for this script."
	echo "## Decryption command line options"
	echo "# --dec-yn				Var_dec_yn=\"${Var_dec_yn}\""
	echo "# --dec-copy-save-yn			Var_dec_copy_save_yn=\"${Var_dec_copy_save_yn}\""
	echo "# --dec-copy-save-path			Var_dec_copy_save_path=\"${Var_dec_copy_save_path}\""
	echo "# --dec-copy-save-ownership		Var_dec_copy_save_ownership=\"${Var_dec_copy_save_ownership}\""
	echo "# --dec-copy-save-permissions		Var_dec_copy_save_permissions=\"${Var_dec_copy_save_permissions}\""
	echo "# --dec-bulk-check-count-max		Var_dec_bulk_check_count_max=\"${Var_dec_bulk_check_count_max}\""
	echo "# --dec-bulk-check-sleep		Var_dec_bulk_check_sleep=\"${Var_dec_bulk_check_sleep}\""
	echo "# --dec-gpg-opts			Var_dec_gpg_opts=\"${Var_dec_gpg_opts}\""
	echo "# --dec-pipe-make-yn			Var_dec_pipe_make_yn=\"${Var_dec_pipe_make_yn}\""
	echo "# --dec-pipe-file			Var_dec_pipe_file=\"${Var_dec_pipe_file}\""
	echo "# --dec-pipe-permissions		Var_dec_pipe_permissions=\"${Var_dec_pipe_permissions}\""
	echo "# --dec-pipe-ownership			Var_dec_pipe_ownership=\"${Var_dec_pipe_ownership}\""
	echo "# --dec-parsing-bulk-out-dir		Var_dec_parsing_bulk_out_dir=\"${Var_dec_parsing_bulk_out_dir}\""
	echo "# --dec-parsing-disown-yn		Var_dec_parsing_disown_yn=\"${Var_dec_parsing_disown_yn}\""
	echo "# --dec-parsing-save-output-yn		Var_dec_parsing_save_output_yn=\"${Var_dec_parsing_save_output_yn}\""
	echo "# --dec-parsing-output-file		Var_dec_parsing_output_file=\"${Var_dec_parsing_output_file}\""
	echo "# --dec-parsing-quit-string		Var_dec_parsing_quit_string=\"${Var_dec_parsing_quit_string}\""
	echo "# --dec-pass				Var_dec_pass=\"${Var_dec_pass}\""
	echo "# --dec-search-string			Var_dec_search_string=\"${Var_dec_search_string}\""
	echo "## Encryption command line options"
	echo "# --enc-yn				Var_enc_yn=\"${Var_enc_yn}\""
	echo "# --enc-copy-save-yn			Var_enc_copy_save_yn=\"${Var_enc_copy_save_yn}\""
	echo "# --enc-copy-save-path			Var_enc_copy_save_path=\"${Var_enc_copy_save_path}\""
	echo "# --enc-copy-save-ownership		Var_enc_copy_save_ownership=\"${Var_enc_copy_save_ownership}\""
	echo "# --enc-copy-save-permissions		Var_enc_copy_save_permissions=\"${Var_enc_copy_save_permissions}\""
	echo "# --enc-gpg-opts			Var_enc_gpg_opts=\"${Var_enc_gpg_opts}\""
	echo "# --enc-parsing-bulk-out-dir		Var_enc_parsing_bulk_out_dir=\"${Var_enc_parsing_bulk_out_dir}\""
	echo "# --enc-parsing-bulk-output-suffix	Var_enc_parsing_bulk_output_suffix=\"${Var_enc_parsing_bulk_output_suffix}\""
	echo "# --enc-parsing-disown-yn		Var_enc_parsing_disown_yn=\"${Var_enc_parsing_disown_yn}\""
	echo "# --enc-parsing-filter-input-yn		Var_enc_parsing_filter_input_yn=\"${Var_enc_parsing_filter_input_yn}\""
	echo "# --enc-parsing-filter-comment-pattern	Var_enc_parsing_filter_comment_pattern=\"${Var_enc_parsing_filter_comment_pattern}\""
	echo "# --enc-parsing-filter-allowed-chars	Var_enc_parsing_filter_allowed_chars=\"${Var_enc_parsing_filter_allowed_chars}\""
	echo "# --enc-parsing-recipient		Var_enc_parsing_recipient=\"${Var_enc_parsing_recipient}\""
	echo "# --enc-parsing-output-file		Var_enc_parsing_output_file=\"${Var_enc_parsing_output_file}\""
	echo "# --enc-parsing-output-rotate-yn	Var_enc_parsing_output_rotate_yn=\"${Var_enc_parsing_output_rotate_yn}\""
	echo "# --enc-parsing-output-rotate-actions	Var_enc_parsing_output_rotate_actions=\"${Var_enc_parsing_output_rotate_actions}\""
	echo "# --enc-parsing-output-rotate-recipient	Var_enc_parsing_output_rotate_recipient=\"${Var_enc_parsing_output_rotate_recipient}\""
	echo "# --enc-parsing-output-max-size		Var_enc_parsing_output_max_size=\"${Var_enc_parsing_output_max_size}\""
	echo "# --enc-parsing-output-check-frequency	Var_enc_parsing_output_check_frequency=\"${Var_enc_parsing_output_check_frequency}\""
	echo "# --enc-parsing-save-output-yn		Var_enc_parsing_save_output_yn=\"${Var_enc_parsing_save_output_yn}\""
	echo "# --enc-parsing-quit-string		Var_enc_parsing_quit_string=\"${Var_enc_parsing_quit_string}\""
	echo "# --enc-pipe-permissions		Var_enc_pipe_permissions=\"${Var_enc_pipe_permissions}\""
	echo "# --enc-pipe-ownership			Var_enc_pipe_ownership=\"${Var_enc_pipe_ownership}\""
	echo "# --enc-pipe-file			Var_enc_pipe_file=\"${Var_enc_pipe_file}\""
	echo "# --enc-parsing-output-permissions	Var_enc_parsing_output_permissions=\"${Var_enc_parsing_output_permissions}\""
	echo "# --enc-parsing-output-ownership	Var_enc_parsing_output_ownership=\"${Var_enc_parsing_output_ownership}\""
	echo "## File path variables"
	echo "# ---Var_dev_null			Var_dev_null=\"${Var_dev_null}\""
}
Func_script_license_customizer(){
	Func_message "## Salutations ${Var_script_current_user:-$(id -un)}, the following license" '0' '42'
	Func_message "#  only applies to this script [${Var_script_title}]. Software external to but" '0' '42'
	Func_message "#  used by [${Var_script_name}] are protected under their own licensing" '0' '42'
	Func_message "#  usage agreements. The authors of this project assume **no** rights" '0' '42'
	Func_message "#  to modify software licensing agreements external to [${Var_script_name}]" '0' '42'
	Func_message '## GNU AGPL v3 Notice start' '0' '42'
	Func_message "# ${Var_script_name}, ${Var_script_description}" '0' '42'
	Func_message "#  Copyright (C) 2016 ${Var_authors_name}" '0' '42'
	Func_message '# This program is free software: you can redistribute it and/or modify' '0' '42'
	Func_message '#  it under the terms of the GNU Affero General Public License as' '0' '42'
	Func_message '#  published by the Free Software Foundation, version 3 of the' '0' '42'
	Func_message '#  License.' '0' '42'
	Func_message '# You should have received a copy of the GNU Afferno General Public License' '0' '42'
	Func_message '# along with this program. If not, see <http://www.gnu.org/licenses/>.' '0' '42'
	Func_message "#  Contact authors of [${Var_script_name}] at: ${Var_authors_contact}" '0' '42'
	Func_message '# GNU AGPL v3 Notice end' '0' '42'
	if [ -r "${Var_script_dir}/Licenses/GNU_AGPLv3_Code.md" ]; then
		Func_message '## Found local license file, prompting to display...' '0' '42'
		Func_prompt_continue "Func_script_license_customizer"
		less -R5 "${Var_script_dir}/Licenses/GNU_AGPLv3_Code.md"
	else
		${Var_echo_exec_path} -en "Please input the downloaded source directory for ${Var_script_name}: "
		read -r _responce
		if [ -d "${_responce}" ] && [ -r "${_responce}/Licenses/GNU_AGPLv3_Code.md" ]; then
			Func_message '## Found local license file, prompting to display...' '0' '42'
			Func_prompt_continue "Func_script_license_customizer"
			fold -sw $((${Var_columns}-8)) "${_responce}/Licenses/GNU_AGPLv3_Code.md" | less -R5
		else
			Func_message '## Unable to find full license, see linke in above short version or find full license under downloaded source directory for this script.' '0' '42'
		fi
	fi
}
Func_message(){
	_message="${1}"
	_debug_level="${2:-${Var_debug_level}}"
	_log_level="${3:-${Var_log_level}}"
	if [ "${#_message}" != "0" ]; then
		if [ "${_debug_level}" = "${Var_debug_level}" ] || [ "${Var_debug_level}" -gt "${_debug_level}" ]; then
			_folded_message="$(fold -sw $((${Var_columns}-6)) <<<"${_message}" | sed -e "s/^.*$/$(${Var_echo} -n "#DBL-${_debug_level}") &/g")"
			${Var_cat} <<<"${_folded_message}"
		fi
	fi
	if [ "${#_message}" != "0" ]; then
		if [ "${Var_log_level}" -gt "${_log_level}" ]; then
			${Var_cat} <<<"${_message}" >> "${Var_script_log_path}"
		fi
	fi
}
Func_assign_arg(){
	_variable="${1}"
	_value="${2}"
	Func_message "# Func_assign_arg running: declare -g \"${_variable}\"=\"${_value}\"" '3' '4'
	declare -g "${_variable}=${_value}"
	Func_save_variables "${_variable}" "${_value}"
	unset _variable
	unset _value
}
Func_save_variables(){
	_variable="${1}"
	_value="${2}"
	case "${Var_save_variables_yn}" in
		Y|y|Yes|yes|YES)
			${Var_cat} >> "${Var_source_var_file}" <<EOF
declare -g ${_variable}="${_value}"
EOF
		;;
	esac
}
## Support functions
#Func_set_owner_permissions "perm" "own" "file"
Func_set_owner_permissions(){
	_desired_permissions="${1}"
	_desired_ownership="${2}"
	_path_to_check="${3}"
	if [ -f "${_path_to_check}" ] || [ -d "${_path_to_check}" ] || [ -p "${_path_to_check}" ]; then
		_current_permissions="$(stat -c "%a" "${_path_to_check}")"
		_current_owner_username="$(stat -c "%U" "${_path_to_check}")"
		_current_owner_groupname="$(stat -c "%G" "${_path_to_check}")"
		_current_owner_userid="$(stat -c "%u" "${_path_to_check}")"
		_current_owner_groupid="$(stat -c "%g" "${_path_to_check}")"
		if [ "${_desired_permissions}" != "${_current_permissions}" ]; then
			Func_message "# Func_set_owner_permissions running: ${Var_chmod} ${_desired_permissions} \"${_path_to_check}\"" '3' '4'
			${Var_chmod} ${_desired_permissions} "${_path_to_check}"
		else
			Func_message "# Func_set_owner_permissions reports permissions [${_desired_permissions}=${_current_permissions}] for file: ${_path_to_check}" '3' '4'
		fi
		if [ "${_desired_ownership}" != "${_current_owner_username}:${_current_owner_groupname}" ] || [ "${_desired_ownership}" != "${_current_owner_userid}:${_current_owner_groupid}" ]; then
			Func_message "# Func_set_owner_permissions running: ${Var_chown} ${_desired_ownership} \"${_path_to_check}\"" '3' '4'
			${Var_chown} ${_desired_ownership} "${_path_to_check}"
		else
			Func_message "# Func_set_owner_permissions reports ownership [${_desired_ownership}=${_current_owner_username}:${_current_owner_groupname} or ${_current_owner_userid}:${_current_owner_groupid}] for file: ${_path_to_check}" '3' '4'
		fi
	else
		Func_message "# Func_set_owner_permissions can not find: ${_path_to_check}" '3' '4'
		Func_message "# Func_set_owner_permissions running: exit 1" '3' '4'
		exit 1
	fi
}
## Encryption functions
Func_enc_make_named_pipe(){
	if ! [ -p "${Var_enc_pipe_file}" ]; then
		Func_message "# Func_enc_make_named_pipe running: ${Var_mkfifo} \"${Var_enc_pipe_file}\" || exit 1" '2' '3'
		${Var_mkfifo} "${Var_enc_pipe_file}" || exit 1
	fi
	Func_message "# Func_enc_make_named_pipe running: Func_set_owner_permissions \"${Var_enc_pipe_permissions}\" \"${Var_enc_pipe_ownership}\" \"${Var_enc_pipe_file}\"" '2' '3'
	Func_set_owner_permissions "${Var_enc_pipe_permissions}" "${Var_enc_pipe_ownership}" "${Var_enc_pipe_file}"
}
Func_enc_rotate_output_file(){
	_parsing_output_file="${1:-${Var_enc_parsing_output_file}}"
	_output_rotate_yn="${2:-${Var_enc_parsing_output_rotate_yn}}"
	_output_max_size="${3:-${Var_enc_parsing_output_max_size}}"
	_output_rotate_actions="${4:-${Var_enc_parsing_output_rotate_actions}}"
	_output_rotate_recipient="${5:-${Var_enc_parsing_output_rotate_recipient}}"
	case "${_output_rotate_yn}" in
		y|Y|yes|Yes|YES)
			if [ -f "${_parsing_output_file}" ]; then
				_file_size="$(du --bytes "${_parsing_output_file}" | awk '{print $1}' | head -n1)"
				if [ "${_file_size}" -gt "${_output_max_size}" ]; then
					_timestamp="$(date -u +%s)"
					for _actions in ${_output_rotate_actions//,/ }; do
						case "${_actions}" in
							mv|move)
								Func_message "# Func_enc_rotate_output_file running: ${Var_mv} \"${_parsing_output_file}\" \"${_parsing_output_file}.${_timestamp}\"" '4' '5'
								${Var_mv} "${_parsing_output_file}" "${_parsing_output_file}.${_timestamp}"
							;;
							compress-encrypt|encrypt)
								Func_message "# Func_enc_rotate_output_file running: ${Var_tar} -cz - \"${_parsing_output_file}\" | ${Var_gpg} --encrypt --recipient \"${_output_rotate_recipient}\" --output \"${_parsing_output_file}.${_timestamp}.tgz.gpg\"" '4' '5'
								${Var_tar} -cz - "${_parsing_output_file}" | ${Var_gpg} --encrypt --recipient "${_output_rotate_recipient}" --output "${_parsing_output_file}.${_timestamp}.tgz.gpg"
							;;
							encrypted-email)
								Func_message "# Func_enc_rotate_output_file running: ${Var_tar} -cz - \"${_parsing_output_file}\" | ${Var_gpg} --encrypt --recipient \"${_output_rotate_recipient}\" --output \"${_parsing_output_file}.${_timestamp}.tgz.gpg\"" '4' '5'
								${Var_tar} -cz - "${_parsing_output_file}" | ${Var_gpg} --encrypt --recipient "${_output_rotate_recipient}" --output "${_parsing_output_file}.${_timestamp}.tgz.gpg"
								Func_message "# Func_enc_rotate_output_file running: ${Var_echo} \"Sent at ${_timestamp}\" | mutt -s \"${_parsing_output_file}.${_timestamp}.tar.gz.gpg\" -a \"${_parsing_output_file}.${_timestamp}.tar.gz.gpg\" \"${_output_rotate_recipient}\"" '4' '5'
								${Var_echo} "Sent at ${_timestamp}" | mutt -s "${_parsing_output_file}.${_timestamp}.tar.gz.gpg" -a "${_parsing_output_file}.${_timestamp}.tar.gz.gpg" "${_output_rotate_recipient}"
							;;
							compressed-email)
								Func_message "# Func_enc_rotate_output_file running: ${Var_tar} -cz \"${_parsing_output_file}\" \"${_parsing_output_file}.${_timestamp}.tar.gz\"" '4' '5'
								${Var_tar} -cz "${_parsing_output_file}" "${_parsing_output_file}.${_timestamp}.tar.gz"
								Func_message "# Func_enc_rotate_output_file running: ${Var_echo} \"Sent at ${_timestamp}\" | mutt -s \"${_parsing_output_file}.${_timestamp}.tar.gz\" -a \"${_parsing_output_file}.${_timestamp}.tar.gz\" \"${_output_rotate_recipient}\"" '4' '5'
								${Var_echo} "Sent at ${_timestamp}" | mutt -s "${_parsing_output_file}.${_timestamp}.tar.gz" -a "${_parsing_output_file}.${_timestamp}.tar.gz" "${_output_rotate_recipient}"
							;;
							compress)
								Func_message "# Func_enc_rotate_output_file running: ${Var_tar} -cz \"${_parsing_output_file}\" \"${_parsing_output_file}.${_timestamp}.tar.gz\"" '4' '5'
								${Var_tar} -cz "${_parsing_output_file}" "${_parsing_output_file}.${_timestamp}.tar.gz"
							;;
							remove|rm|remove-old)
								Func_message "# Func_enc_rotate_output_file running: ${Var_rm} -f \"${_parsing_output_file}\"" '4' '5'
								${Var_rm} -f "${_parsing_output_file}"
							;;
						esac
					done
				fi
			fi
		;;
	esac
}
Func_enc_map_read_array_to_output(){
	_file_to_map="$1"
	mapfile -t _lines < "${_file_to_map}"
	let _count=0
	until [ "${_count}" = "${#_lines[@]}" ]; do
		if [ "${Var_enc_parsing_quit_string}" = "${_lines[${_count}]}" ]; then
			${Var_cat} <<<"${_lines[${_count}]}"
			break
		else
			case "${Var_enc_parsing_filter_input_yn}" in
				y|Y|yes|Yes|YES)
					case "${_lines[${_count}]}" in
						${Var_enc_parsing_filter_comment_pattern})
							${Var_cat} <<<"${_lines[${_count}]//${Var_enc_parsing_filter_allowed_chars}/}"
						;;
						*)
							${Var_cat} <<<"# ${_lines[${_count}]//${Var_enc_parsing_filter_allowed_chars}/}"
						;;
					esac
					let _count++
				;;
				*)
					${Var_cat} <<<"${_lines[${_count}]}"
					let _count++
				;;
			esac
		fi
	done
}
Func_enc_pipe_parser_loop(){
	_enc_gpg_opts="${Var_enc_gpg_opts} --recipient ${Var_enc_parsing_recipient// / --recipient }"
	let _check_count=0
	while [ -p "${Var_enc_pipe_file}" ]; do
		_mapped_array="$(Func_enc_map_read_array_to_output "${Var_enc_pipe_file}")"
		if [ "${#_mapped_array}" != "0" ] && [ "${Var_enc_parsing_quit_string}" != "${_mapped_array}" ]; then
			case "${Var_enc_parsing_save_output_yn}" in
				y|Y|yes|Yes)
					if [ -f "${_mapped_array}" ]; then
						if ! [ -d "${Var_enc_parsing_bulk_out_dir}" ]; then
							Func_message "# Func_enc_pipe_parser_loop running: ${Var_mkdir} -p \"${Var_enc_parsing_bulk_out_dir}\"" '2' '3'
							${Var_mkdir} -p "${Var_enc_parsing_bulk_out_dir}"
						fi
						Var_star_date="$(date -u +%s)"
						Func_message "# Func_enc_pipe_parser_loop running: ${Var_cat} \"\${_mapped_array}\" | ${Var_gpg} ${_enc_gpg_opts} >> \"${Var_enc_parsing_bulk_out_dir}/${Var_star_date}_\${_mapped_array##*/}${Var_enc_parsing_bulk_output_suffix}\"" '2' '3'
						${Var_cat} "${_mapped_array}" | ${Var_gpg} ${_enc_gpg_opts} >> "${Var_enc_parsing_bulk_out_dir}/${Var_star_date}_${_mapped_array##*/}${Var_enc_parsing_bulk_output_suffix}"
					elif [ -d "${_mapped_array}" ]; then
						if ! [ -d "${Var_enc_parsing_bulk_out_dir}" ]; then
							Func_message "# Func_enc_pipe_parser_loop running: ${Var_mkdir} -p \"${Var_enc_parsing_bulk_out_dir}\"" '2' '3'
							${Var_mkdir} -p "${Var_enc_parsing_bulk_out_dir}"
						fi
						_dir_name="${_mapped_array##*/}"
						_dir_name="${_dir_name%/*}"
						Var_star_date="$(date -u +%s)"
						Func_message "# Func_enc_pipe_parser_loop running: ${Var_tar} -cz - \"\${_mapped_array}\" | ${Var_gpg} ${_enc_gpg_opts} > ${Var_enc_parsing_bulk_out_dir}/${Var_star_date}_${_dir_name}.tgz${Var_enc_parsing_bulk_output_suffix}" '2' '3'
						${Var_tar} -cz - "${_mapped_array}" | ${Var_gpg} ${_enc_gpg_opts} > "${Var_enc_parsing_bulk_out_dir}/${Var_star_date}_${_dir_name}.tgz${Var_enc_parsing_bulk_output_suffix}"
					else
						if [ -p "${Var_enc_parsing_output_file}" ]; then
							Func_message "# Func_enc_pipe_parser_loop running: ${Var_cat} <<<\"\${_mapped_array}\" | ${Var_gpg} ${_enc_gpg_opts} > \"${Var_enc_parsing_output_file}\"" '2' '3'
							${Var_cat} <<<"${_mapped_array}" | ${Var_gpg} ${_enc_gpg_opts} > "${Var_enc_parsing_output_file}"
						else
							if ! [ -f "${Var_enc_parsing_output_file}" ]; then
								Func_message "# Func_enc_pipe_parser_loop running: ${Var_touch} \"${Var_enc_parsing_output_file}\"" '2' '3'
								${Var_touch} "${Var_enc_parsing_output_file}"
								Func_message "# Func_enc_pipe_parser_loop running: Func_set_owner_permissions \"${Var_enc_parsing_output_permissions}\" \"${Var_enc_parsing_output_ownership}\" \"${Var_enc_parsing_output_file}\"" '2' '3'
								Func_set_owner_permissions "${Var_enc_parsing_output_permissions}" "${Var_enc_parsing_output_ownership}" "${Var_enc_parsing_output_file}"
							fi
							Func_message "# Func_enc_pipe_parser_loop running: ${Var_cat} <<<\"\${_mapped_array}\" | ${Var_gpg} ${_enc_gpg_opts} >> \"${Var_enc_parsing_output_file}\"" '2' '3'
							${Var_cat} <<<"${_mapped_array}" | ${Var_gpg} ${_enc_gpg_opts} >> "${Var_enc_parsing_output_file}"
							if [ "${_check_count}" -gt "${Var_enc_parsing_output_check_frequency}" ] || [ "${_check_count}" = "${Var_enc_parsing_output_check_frequency}" ]; then
								Func_message "# Func_enc_pipe_parser_loop running: Func_enc_rotate_output_file \"${Var_enc_parsing_output_file}\" \"${Var_enc_parsing_output_rotate_yn}\" \"${Var_enc_parsing_output_max_size}\" \"${Var_enc_parsing_output_rotate_actions}\" \"${Var_enc_parsing_output_rotate_recipient}\"" '2' '3'
								Func_enc_rotate_output_file "${Var_enc_parsing_output_file}" "${Var_enc_parsing_output_rotate_yn}" "${Var_enc_parsing_output_max_size}" "${Var_enc_parsing_output_rotate_actions}" "${Var_enc_parsing_output_rotate_recipient}"
							fi
							let _check_count++
						fi
					fi
				;;
				*)
					Func_message "# Func_enc_pipe_parser_loop running: ${Var_cat} <<<\"\${_mapped_array}\" | ${Var_gpg} ${_enc_gpg_opts}" '2' '3'
					${Var_cat} <<<"${_mapped_array}" | ${Var_gpg} ${_enc_gpg_opts}
				;;
			esac
		elif [ "${Var_enc_parsing_quit_string}" = "${_mapped_array}" ]; then
			case "${Var_enc_parsing_disown_yn}" in
				Y|y|Yes|yes|YES)
					if [ -p "${Var_enc_pipe_file}" ]; then
						Func_message "# Func_enc_pipe_parser_loop running: ${Var_rm} \"${Var_enc_pipe_file}\"" '2' '3'
						${Var_rm} "${Var_enc_pipe_file}"
					else
						Func_message "# Func_enc_pipe_parser_loop reports: no pipe to remove at [${Var_enc_pipe_file}]" '2' '3'
					fi
				;;
				*)
					Func_message "# Func_enc_pipe_parser_loop reports: trap set outside [Map_read_input_to_array] function parsing loop" '2' '3'
				;;
			esac
			break
		elif ! [ -p "${Var_enc_pipe_file}" ]; then
			Func_message "# Func_enc_pipe_parser_loop reports: missing pipe ${Var_enc_pipe_file}" '2' '3'
			break
		fi
	done
	unset _check_count
}
Func_enc_write_script_copy(){
	case "${Var_enc_copy_save_yn}" in
		Y|y|Yes|yes|YES)
			if [ -f "${Var_enc_copy_save_path}" ]; then
				Func_message "# Func_enc_write_script_copy reports script copy already exsists: ${Var_enc_copy_save_path}" '2' '3'
			else
				Func_message "# Func_enc_write_script_copy writing script copy: ${Var_enc_copy_save_path}" '2' '3'
				${Var_cat} > "${Var_enc_copy_save_path}" <<EOF
#!/usr/bin/env bash
set +o history
Var_script_dir="\${0%/*}"
Var_script_name="\${0##*/}"
Var_enc_gpg_opts="${Var_enc_gpg_opts}"
Var_enc_parsing_bulk_out_dir="${Var_enc_parsing_bulk_out_dir}"
Var_enc_parsing_bulk_output_suffix="${Var_enc_parsing_bulk_output_suffix}"
Var_enc_parsing_disown_yn="${Var_enc_parsing_disown_yn}"
Var_enc_parsing_filter_input_yn="${Var_enc_parsing_filter_input_yn}"
Var_enc_parsing_filter_comment_pattern='${Var_enc_parsing_filter_comment_pattern}'
Var_enc_parsing_filter_allowed_chars='${Var_enc_parsing_filter_allowed_chars}'
Var_enc_parsing_recipient="${Var_enc_parsing_recipient}"
Var_enc_parsing_output_file="${Var_enc_parsing_output_file}"
Var_enc_parsing_output_rotate_yn="${Var_enc_parsing_output_rotate_yn}"
Var_enc_parsing_output_rotate_actions="${Var_enc_parsing_output_rotate_actions}"
Var_enc_parsing_output_rotate_recipient="${Var_enc_parsing_output_rotate_recipient}"
Var_enc_parsing_output_max_size="${Var_enc_parsing_output_max_size}"
Var_enc_parsing_output_check_frequency="${Var_enc_parsing_output_check_frequency}"
Var_enc_parsing_save_output_yn="${Var_enc_parsing_save_output_yn}"
Var_enc_parsing_quit_string="${Var_enc_parsing_quit_string}"
Var_enc_pipe_permissions="${Var_enc_pipe_permissions}"
Var_enc_pipe_ownership="${Var_enc_pipe_ownership}"
Var_enc_pipe_file="${Var_enc_pipe_file}"
#Var_enc_parsing_output_permissions="${Var_enc_parsing_output_permissions}
Var_dev_null="${Var_dev_null}"
${Var_echo} "### ... Starting [\${Var_script_name}] at \$(date) ... ###"
Func_enc_make_named_pipe(){
	if ! [ -p "\${Var_enc_pipe_file}" ]; then
		${Var_mkfifo} "\${Var_enc_pipe_file}" || exit 1
	fi
	${Var_chmod} "\${Var_enc_pipe_permissions}" "\${Var_enc_pipe_file}" || exit 1
	${Var_chown} "\${Var_enc_pipe_ownership}" "\${Var_enc_pipe_file}" || exit 1
}
Func_enc_rotate_output_file(){
	_parsing_output_file="\${1:-\${Var_enc_parsing_output_file}}"
	_output_rotate_yn="\${2:-\${Var_enc_parsing_output_rotate_yn}}"
	_output_max_size="\${3:-\${Var_enc_parsing_output_max_size}}"
	_output_rotate_actions="\${4:-\${Var_enc_parsing_output_rotate_actions}}"
	_output_rotate_recipient="\${5:-\${Var_enc_parsing_output_rotate_recipient}}"
	case "\${_output_rotate_yn}" in
		y|Y|yes|Yes|YES)
			if [ -f "\${_parsing_output_file}" ]; then
				_file_size="\$(du --bytes "\${_parsing_output_file}" | awk '{print \$1}' | head -n1)"
				if [ "\${_file_size}" -gt "\${_output_max_size}" ]; then
					_timestamp="\$(date -u +%s)"
					for _actions in \${_output_rotate_actions//,/ }; do
						case "\${_actions}" in
							mv|move)
								${Var_mv} "\${_parsing_output_file}" "\${_parsing_output_file}.\${_timestamp}"
							;;
							compress-encrypt|encrypt)
								${Var_tar} -cz - "\${_parsing_output_file}" | ${Var_gpg} --encrypt --recipient "\${_output_rotate_recipient}" --output "\${_parsing_output_file}.\${_timestamp}.tgz.gpg"
							;;
							encrypted-email)
								${Var_tar} -cz - "\${_parsing_output_file}" | ${Var_gpg} --encrypt --recipient "\${_output_rotate_recipient}" --output "\${_parsing_output_file}.\${_timestamp}.tgz.gpg"
								${Var_echo} "Sent at \${_timestamp}" | mutt -s "\${_parsing_output_file}.\${_timestamp}.tar.gz.gpg" -a "\${_parsing_output_file}.\${_timestamp}.tar.gz.gpg" "\${_output_rotate_recipient}"
							;;
							compressed-email)
								${Var_tar} -cz "\${_parsing_output_file}" "\${_parsing_output_file}.\${_timestamp}.tar.gz"
								${Var_echo} "Sent at \${_timestamp}" | mutt -s "\${_parsing_output_file}.\${_timestamp}.tar.gz" -a "\${_parsing_output_file}.\${_timestamp}.tar.gz" "\${_output_rotate_recipient}"
							;;
							compress)
								${Var_tar} -cz "\${_parsing_output_file}" "\${_parsing_output_file}.\${_timestamp}.tar.gz"
							;;
							remove|rm|remove-old)
								${Var_rm} -f "\${_parsing_output_file}"
							;;
						esac
					done
				fi
			fi
		;;
	esac
}
Func_enc_map_read_array_to_output(){
	_file_to_map="\$1"
	mapfile -t _lines < "\${_file_to_map}"
	let _count=0
	until [ "\${_count}" = "\${#_lines[@]}" ]; do
		if [ "\${Var_enc_parsing_quit_string}" = "\${_lines[\${_count}]}" ]; then
			${Var_cat} <<<"\${_lines[\${_count}]}"
			break
		else
			case "\${Var_enc_parsing_filter_input_yn}" in
				y|Y|yes|Yes|YES)
					case "\${_lines[\${_count}]}" in
						\${Var_enc_parsing_filter_comment_pattern})
							${Var_cat} <<<"\${_lines[\${_count}]//\${Var_enc_parsing_filter_allowed_chars}/}"
						;;
						*)
							${Var_cat} <<<"# \${_lines[\${_count}]//\${Var_enc_parsing_filter_allowed_chars}/}"
						;;
					esac
					let _count++
				;;
				*)
					${Var_cat} <<<"\${_lines[\${_count}]}"
					let _count++
				;;
			esac
		fi
	done
}
Func_enc_pipe_parser_loop(){
	_enc_gpg_opts="\${Var_enc_gpg_opts} --recipient \${Var_enc_parsing_recipient// / --recipient }"
	let _check_count=0
	while [ -p "\${Var_enc_pipe_file}" ]; do
		_mapped_array="\$(Func_enc_map_read_array_to_output "\${Var_enc_pipe_file}")"
		if [ "\${#_mapped_array}" != "0" ] && [ "\${Var_enc_parsing_quit_string}" != "\${_mapped_array}" ]; then
			case "\${Var_enc_parsing_save_output_yn}" in
				y|Y|yes|Yes)
					if [ -f "\${_mapped_array}" ]; then
						if ! [ -d "\${Var_enc_parsing_bulk_out_dir}" ]; then
							${Var_mkdir} -p "\${Var_enc_parsing_bulk_out_dir}"
						fi
						Var_star_date="\$(date -u +%s)"
						${Var_cat} "\${_mapped_array}" | ${Var_gpg} \${_enc_gpg_opts} >> "\${Var_enc_parsing_bulk_out_dir}/\${Var_star_date}_\${_mapped_array##*/}\${Var_enc_parsing_bulk_output_suffix}"
					elif [ -d "\${_mapped_array}" ]; then
						if ! [ -d "\${Var_enc_parsing_bulk_out_dir}" ]; then
							${Var_mkdir} -p "\${Var_enc_parsing_bulk_out_dir}"
						fi
						_dir_name="\${_mapped_array##*/}"
						_dir_name="\${_dir_name%/*}"
						Var_star_date="\$(date -u +%s)"
						${Var_tar} -cz - "\${_mapped_array}" | ${Var_gpg} \${_enc_gpg_opts} > "\${Var_enc_parsing_bulk_out_dir}/\${Var_star_date}_\${_dir_name}.tgz\${Var_enc_parsing_bulk_output_suffix}"
					else
						if [ -p "\${Var_enc_parsing_output_file}" ]; then
							${Var_cat} <<<"\${_mapped_array}" | ${Var_gpg} \${_enc_gpg_opts} > "\${Var_enc_parsing_output_file}"
						else
							if ! [ -f "\${Var_enc_parsing_output_file}" ]; then
								${Var_touch} "\${Var_enc_parsing_output_file}"
								${Var_chmod} "\${Var_enc_parsing_output_permissions}" "\${Var_enc_parsing_output_file}"
								${Var_chown} "\${Var_enc_parsing_output_ownership}" "\${Var_enc_parsing_output_file}"
							fi
							${Var_cat} <<<"\${_mapped_array}" | ${Var_gpg} \${_enc_gpg_opts} >> "\${Var_enc_parsing_output_file}"
							if [ "\${_check_count}" -gt "\${Var_enc_parsing_output_check_frequency}" ] || [ "\${_check_count}" = "\${Var_enc_parsing_output_check_frequency}" ]; then
								Func_enc_rotate_output_file "\${Var_enc_parsing_output_file}" "\${Var_enc_parsing_output_rotate_yn}" "\${Var_enc_parsing_output_max_size}" "\${Var_enc_parsing_output_rotate_actions}" "\${Var_enc_parsing_output_rotate_recipient}"
							fi
							let _check_count++
						fi
					fi
				;;
				*)
					${Var_cat} <<<"\${_mapped_array}" | ${Var_gpg} \${_enc_gpg_opts}
				;;
			esac
		elif [ "\${Var_enc_parsing_quit_string}" = "\${_mapped_array}" ]; then
			case "\${Var_enc_parsing_disown_yn}" in
				Y|y|Yes|yes|YES)
					if [ -p "\${Var_enc_pipe_file}" ]; then
						${Var_rm} "\${Var_enc_pipe_file}"
					fi
				;;
			esac
			break
		elif ! [ -p "\${Var_enc_pipe_file}" ]; then
			break
		fi
	done
	unset _check_count
}
Func_assign_arg(){
	_variable="\${1}"
	_value="\${2}"
	declare -g "\${_variable}=\${_value}"
	unset _variable
	unset _value
}
Func_check_args(){
	_arr_input=( "\${@}" )
	let _arr_count=0
	until [ "\${#_arr_input[@]}" = "\${_arr_count}" ]; do
		_arg="\${_arr_input[\${_arr_count}]}"
		case "\${_arg%=*}" in
			--enc-gpg-opts|Var_enc_gpg_opts)
				Func_assign_arg "Var_enc_gpg_opts" "\${_arg#*=}"
			;;
			--enc-parsing-bulk-out-dir|Var_enc_parsing_bulk_out_dir)
				Func_assign_arg "Var_enc_parsing_bulk_out_dir" "\${_arg#*=}"
			;;
			--enc-parsing-bulk-output-suffix|Var_enc_parsing_bulk_output_suffix)
				Func_assign_arg "Var_enc_parsing_bulk_output_suffix" "\${_arg#*=}"
			;;
			--enc-parsing-disown-yn|Var_enc_parsing_disown_yn)
				Func_assign_arg "Var_enc_parsing_disown_yn" "\${_arg#*=}"
			;;
			--enc-parsing-filter-input-yn|Var_enc_parsing_filter_input_yn)
				Func_assign_arg "Var_enc_parsing_filter_input_yn" "\${_arg#*=}"
			;;
			--enc-parsing-filter-comment-pattern|Var_enc_parsing_filter_comment_pattern)
				Func_assign_arg "Var_enc_parsing_filter_comment_pattern" "\${_arg#*=}"
			;;
			--enc-parsing-filter-allowed-chars|Var_enc_parsing_filter_allowed_chars)
				Func_assign_arg "Var_enc_parsing_filter_allowed_chars" "\${_arg#*=}"
			;;
			--enc-parsing-recipient|Var_enc_parsing_recipient)
				Func_assign_arg "Var_enc_parsing_recipient" "\${_arg#*=}"
			;;
			--enc-parsing-output-file|Var_enc_parsing_output_file)
				Func_assign_arg "Var_enc_parsing_output_file" "\${_arg#*=}"
			;;
			--enc-parsing-output-rotate-yn|Var_enc_parsing_output_rotate_yn)
				Func_assign_arg "Var_enc_parsing_output_rotate_yn" "\${_arg#*=}"
			;;
			--enc-parsing-output-rotate-actions|Var_enc_parsing_output_rotate_actions)
				Func_assign_arg "Var_enc_parsing_output_rotate_actions" "\${_arg#*=}"
			;;
			--enc-parsing-output-rotate-recipient|Var_enc_parsing_output_rotate_recipient)
				Func_assign_arg "Var_enc_parsing_output_rotate_recipient" "\${_arg#*=}"
			;;
			--enc-parsing-output-max-size|Var_enc_parsing_output_max_size)
				Func_assign_arg "Var_enc_parsing_output_max_size" "\${_arg#*=}"
			;;
			--enc-parsing-output-check-frequency|Var_enc_parsing_output_check_frequency)
				Func_assign_arg "Var_enc_parsing_output_check_frequency" "\${_arg#*=}"
			;;
			--enc-parsing-save-output-yn|Var_enc_parsing_save_output_yn)
				Func_assign_arg "Var_enc_parsing_save_output_yn" "\${_arg#*=}"
			;;
			--enc-parsing-output-permissions|Var_enc_parsing_output_permissions)
				Func_assign_arg "Var_enc_parsing_output_permissions" "\${_arg#*=}"
			;;
			--enc-parsing-output-ownership|Var_enc_parsing_output_ownership)
				Func_assign_arg "Var_enc_parsing_output_ownership" "\${_arg#*=}"
			;;
			--enc-parsing-quit-string|Var_enc_parsing_quit_string)
				Func_assign_arg "Var_enc_parsing_quit_string" "\${_arg#*=}"
			;;
			--enc-pipe-permissions|Var_enc_pipe_permissions)
				Func_assign_arg "Var_enc_pipe_permissions" "\${_arg#*=}"
			;;
			--enc-pipe-ownership|Var_enc_pipe_ownership)
				Func_assign_arg "Var_enc_pipe_ownership" "\${_arg#*=}"
			;;
			--enc-pipe-file|Var_enc_pipe_file)
				Func_assign_arg "Var_enc_pipe_file" "\${_arg#*=}"
			;;
			--source-var-file|Var_source_var_file)
				Func_assign_arg "Var_source_var_file" "\${_arg#*=}"
				if [ -f "\${Var_source_var_file}" ]; then
					source "\${Var_source_var_file}"
				fi
			;;
			---*)
				_extra_var="\${_arg%=*}"
				_extra_arg="\${_arg#*=}"
				Func_assign_arg "\${_extra_var/---/}" "\${_extra_arg}"
			;;
			*)
				declare -ag "Arr_extra_input+=( \${_arg} )"
			;;
		esac
		let _arr_count++
	done
	unset _arr_count
}
Func_main(){
	_input=( "\$@" )
	if [ "\${#_input[@]}" != "0" ]; then
		Func_check_args "\${_input[@]}"
	fi
	case "\${Var_enc_parsing_disown_yn}" in
		Y|y|Yes|yes|YES)
			${Var_echo} "## \${Var_script_name} will differ cleanup trap assignment until reading from named pipe [\${Var_enc_pipe_file}] has finished..."
		;;
		*)
			${Var_echo} "## \${Var_script_name} will set exit trap now."
			trap '${Var_rm} "\${Var_enc_pipe_file}"' EXIT
		;;
	esac
	Func_enc_make_named_pipe
	case "\${Var_enc_parsing_disown_yn}" in
		Y|y|Yes|yes|YES)
			Func_enc_pipe_parser_loop >"\${Var_dev_null}" 2>&1 &
			PID_loop=\$!
			disown "\${PID_loop}"
			${Var_echo} "## \${Var_script_name} disowned PID [\${PID_loop}] parsing loops"
			if [ "\${#Arr_extra_input[@]}" != "0" ] && [ -p "\${Var_enc_pipe_file}" ]; then
				${Var_cat} <<<"\${Arr_extra_input[*]}" > "\${Var_enc_pipe_file}"
			fi
		;;
		*)
			${Var_echo} "## \${Var_script_name} will start parsing loop in this terminal"
			Func_enc_pipe_parser_loop
			${Var_echo} "# Quitting \${Var_script_name} listener"
			set -o history
		;;
	esac
}
Func_main "\$@"
${Var_echo} "# \${Var_script_dir}/\${Var_script_name} exited [\$?] at: \$(date)"

EOF

				Func_message "# Func_enc_write_script_copy running: Func_set_owner_permissions \"${Var_enc_copy_save_permissions}\" \"${Var_enc_copy_save_ownership}\" \"${Var_enc_copy_save_path}\"" '2' '3'
				Func_set_owner_permissions "${Var_enc_copy_save_permissions}" "${Var_enc_copy_save_ownership}" "${Var_enc_copy_save_path}"
			fi
		;;
		*)
			Func_message "# Func_enc_write_script_copy skipping writing of: ${Var_enc_copy_save_path}" '2' '3'
		;;
	esac
}
## Functions for decryption
Func_dec_make_named_pipe(){
	if ! [ -p "${Var_dec_pipe_file}" ]; then
		Func_message "# Func_dec_make_named_pipe running: ${Var_mkfifo} \"${Var_dec_pipe_file}\" || exit 1" '2' '3'
		${Var_mkfifo} "${Var_dec_pipe_file}" || exit 1
	fi
	Func_message "# Func_dec_make_named_pipe running: Func_set_owner_permissions \"${Var_dec_pipe_permissions}\" \"${Var_dec_pipe_ownership}\" \"${Var_dec_pipe_file}\"" '2' '3'
	Func_set_owner_permissions "${Var_dec_pipe_permissions}" "${Var_dec_pipe_ownership}" "${Var_dec_pipe_file}"
}
Func_dec_pass_the_pass(){
	_pass=( "$@" )
	if [ -f "${_pass[@]}" ]; then
		Func_message "# Func_dec_pass_the_pass running: exec 9<\"\${_pass[@]}\"" '4' '5'
		exec 9<"${_pass[@]}"
	else
		Func_message "# Func_dec_pass_the_pass running: exec 9<(${Var_echo} \"\${_pass[@]}\")" '4' '5'
		exec 9<(${Var_echo} "${_pass[@]}")
	fi
}
Func_dec_expand_array_to_block(){
	_input=( "$@" )
	let _count=0
	until [ "${_count}" = "${#_input[@]}" ]; do
		${Var_echo} "${_input[${_count}]}"
		let _count++
	done
	unset _count
	unset -v _input[@]
}
Func_dec_do_stuff_with_lines(){
	_enc_block=( "$@" )
	_enc_input="$(Func_dec_expand_array_to_block "${_enc_block[@]}")"
	Func_message "# Func_dec_do_stuff_with_lines running: Func_dec_pass_the_pass \"\${Var_dec_pass}\"" '3' '4'
	Func_dec_pass_the_pass "${Var_dec_pass}"
	if [ -p "${Var_dec_parsing_output_file}" ]; then
		Func_message "# Func_dec_do_stuff_with_lines running: ${Var_cat} <<<\"\${_enc_input}\" > \"${Var_dec_parsing_output_file}\"" '3' '4'
		${Var_cat} <<<"${_enc_input}" > "${Var_dec_parsing_output_file}"
	elif [ -f "${Var_dec_parsing_output_file}" ]; then
		if [ "${#Var_dec_search_string}" = "0" ]; then
			Func_message "# Func_dec_do_stuff_with_lines running: ${Var_cat} <<<\"\${_enc_input}\" | ${Var_gpg} ${Var_dec_gpg_opts} >> \"${Var_dec_parsing_output_file}\"" '3' '4'
			${Var_cat} <<<"${_enc_input}" | ${Var_gpg} ${Var_dec_gpg_opts} >> "${Var_dec_parsing_output_file}"
		else
			Func_message "# Func_dec_do_stuff_with_lines running: ${Var_cat} <<<\"\${_enc_input}\" | ${Var_gpg} ${Var_dec_gpg_opts} | grep \"${Var_dec_search_string}\" >> \"${Var_dec_parsing_output_file}\"" '3' '4'
			${Var_cat} <<<"${_enc_input}" | ${Var_gpg} ${Var_dec_gpg_opts} | grep "${Var_dec_search_string}" >> "${Var_dec_parsing_output_file}"
		fi
	else
		if [ "${#Var_dec_search_string}" = "0" ]; then
			Func_message "# Func_dec_do_stuff_with_lines running: ${Var_cat} <<<\"\${_enc_input}\" | ${Var_gpg} ${Var_dec_gpg_opts}" '3' '4'
			${Var_cat} <<<"${_enc_input}" | ${Var_gpg} ${Var_dec_gpg_opts}
		else
			Func_message "# Func_dec_do_stuff_with_lines running: ${Var_cat} <<<\"\${_enc_input}\" | ${Var_gpg} ${Var_dec_gpg_opts} | grep \"${Var_dec_search_string}\"" '3' '4'
			${Var_cat} <<<"${_enc_input}" | ${Var_gpg} ${Var_dec_gpg_opts} | grep "${Var_dec_search_string}"
		fi
	fi
	unset -v _enc_block[@]
	unset _enc_input
	exec 9>&-
}
Func_dec_spoon_feed_armored_packets(){
	_input=( "${@}" )
	_beginning_of_line='-----BEGIN PGP MESSAGE-----'
	_end_of_line='-----END PGP MESSAGE-----'
	if [ -f "${_input[@]}" ]; then
		mapfile -t _arr_input < "${_input[@]}"
	elif [ -p "${_input[@]}" ]; then
		mapfile -t _arr_input < "${_input[@]}"
	else
		mapfile -t _arr_input <<<"${_input[@]}"
	fi
	let _count=0
	until [ "${_count}" = "${#_arr_input[@]}" ]; do
		if [ "${Var_dec_parsing_quit_string}" = "${_arr_input[${_count}]}" ]; then
			if [ -p "${Var_enc_parsing_output_file}" ]; then
				${Var_rm} "${Var_enc_parsing_output_file}"
			fi
			break
		elif [ "${_end_of_line}" = "${_arr_input[${_count}]}" ]; then
			_arr_to_parse+=( "${_arr_input[${_count}]}" )
			let _count++
			Func_message "# Func_dec_spoon_feed_armored_packets running: Func_dec_do_stuff_with_lines \"\${_arr_to_parse[@]}\"" '2' '3'
			Func_dec_do_stuff_with_lines "${_arr_to_parse[@]}"
			unset -v _arr_to_parse[@]
		elif [ "${_beginning_of_line}" = "${_arr_input[${_count}]}" ]; then
			_arr_to_parse=( "${_arr_input[${_count}]}" )
			let _count++
		else
			_arr_to_parse+=( "${_arr_input[${_count}]}" )
			let _count++
		fi

	done
	unset _count
	unset -v _input[@]
	unset -v _arr_input[@]
}
Func_dec_file_or_dir(){
	_encrypted_path="${1}"
	Func_message "# Func_dec_file_or_dir running: Func_dec_pass_the_pass \"\${Var_dec_pass}\"" '5' '6'
	Func_dec_pass_the_pass "${Var_dec_pass}"
	case "${_encrypted_path}" in
		*.tar.gpg)
			_old_pwd="${PWD}"
			_output_dir="${Var_dec_parsing_bulk_out_dir}/${_encrypted_path##*/}"
			_output_dir="${_output_dir%.tar.gpg*}"
			if ! [ -d "${_output_dir}" ]; then
				Func_message "# Func_dec_file_or_dir running: ${Var_mkdir} -p \"${_output_dir}\"" '5' '6'
				${Var_mkdir} -p "${_output_dir}"
				Func_message "# Func_dec_file_or_dir running: cd \"${_output_dir}\"" '5' '6'
				cd "${_output_dir}"
				Func_message "# Func_dec_file_or_dir running: ${Var_gpg} ${Var_dec_gpg_opts} \"${_encrypted_path}\" | ${Var_tar} -xf -" '5' '6'
				${Var_gpg} ${Var_dec_gpg_opts}  "${_encrypted_path}" | ${Var_tar} -xf -
				Func_message "# Func_dec_file_or_dir running: cd \"${_old_pwd}\"" '5' '6'
				cd "${_old_pwd}"
			fi
			unset _old_pwd
		;;
		*.tgz.gpg)
			_old_pwd="${PWD}"
			_output_dir="${Var_dec_parsing_bulk_out_dir}/${_encrypted_path##*/}"
			_output_dir="${_output_dir%.tgz.gpg*}"
			if ! [ -d "${_output_dir}" ]; then
				Func_message "# Func_dec_file_or_dir running: ${Var_mkdir} -p \"${_output_dir}\"" '5' '6'
				${Var_mkdir} -p "${_output_dir}"
				Func_message "# Func_dec_file_or_dir running: cd \"${_output_dir}\"" '5' '6'
				cd "${_output_dir}"
				Func_message "# Func_dec_file_or_dir running: ${Var_gpg} ${Var_dec_gpg_opts} \"${_encrypted_path}\" | ${Var_tar} -xzf -" '5' '6'
				${Var_gpg} ${Var_dec_gpg_opts} "${_encrypted_path}" | ${Var_tar} -xzf -
				Func_message "# Func_dec_file_or_dir running: cd \"${_old_pwd}\"" '5' '6'
				cd "${_old_pwd}"
			fi
			unset _old_pwd
		;;
		*.gpg)
			if ! [ -d "${Var_dec_parsing_bulk_out_dir}" ]; then
				Func_message "# Func_dec_file_or_dir running: ${Var_mkdir} -p \"${Var_dec_parsing_bulk_out_dir}\"" '5' '6'
				${Var_mkdir} -p "${Var_dec_parsing_bulk_out_dir}"
			fi
			_output_file="${Var_dec_parsing_bulk_out_dir}/${_encrypted_path##*/}"
			_output_file="${_output_file%.gpg*}"
			if ! [ -f "${_output_file}" ]; then
				Func_message "# Func_dec_file_or_dir running: ${Var_cat} \"${_encrypted_path}\" | ${Var_gpg} ${Var_dec_gpg_opts} > \"${_output_file}\"" '5' '6'
				${Var_cat} "${_encrypted_path}" | ${Var_gpg} ${Var_dec_gpg_opts} > "${_output_file}"
				unset _output_file
			fi
		;;
	esac
	exec 9>&-
	unset _encrypted_path
}
Func_dec_watch_bulk_dir(){
	_current_sig=""
	let _watch_count=0
	while [ -d "${Var_enc_parsing_bulk_out_dir}" ]; do
		_new_sig="$(find "${Var_enc_parsing_bulk_out_dir}" -xtype f -print0 | xargs -0 sha1sum | awk '{print $1}' | sort | sha1sum | awk '{print $1}')"
		if [ "${_current_sig}" != "${_new_sig}" ]; then
			## This funy way of piping into a while loop should silence SheckCheck
			find "${Var_enc_parsing_bulk_out_dir}" -xtype f | while read _path; do
				Func_message "# Func_dec_watch_bulk_dir running: Func_dec_file_or_dir \"${_path}\"" '3' '4'
				Func_dec_file_or_dir "${_path}"
			done
		fi
		_current_sig="${_new_sig}"
		let _watch_count++
		if [ "${Var_dec_bulk_check_count_max}" != "0" ]; then
			if [ "${_watch_count}" -gt "${Var_dec_bulk_check_count_max}" ]; then
				unset _watch_count
				Func_message "# Func_dec_watch_bulk_dir running: break" '3' '4'
				break
			fi
		fi
		Func_message "# Func_dec_watch_bulk_dir [${_watch_count}] running: sleep ${Var_dec_bulk_check_sleep}" '3' '4'
		sleep ${Var_dec_bulk_check_sleep}
	done
}
Func_dec_watch_file(){
	Func_message "# Func_dec_watch_file parsing: ${Var_enc_parsing_output_file}" '3' '4'
	if [ -p "${Var_enc_parsing_output_file}" ]; then
		Func_message "# Func_dec_watch_file detected pipe: ${Var_enc_parsing_output_file}" '3' '4'
		while [ -p "${Var_enc_parsing_output_file}" ]; do
			Func_dec_spoon_feed_armored_packets "${Var_enc_parsing_output_file}"
			if ! [ -p "${Var_enc_parsing_output_file}" ]; then
				break
			fi
		done
	elif [ -f "${Var_enc_parsing_output_file}" ]; then
		Func_message "# Func_dec_watch_file running: Func_dec_spoon_feed_armored_packets \"${Var_enc_parsing_output_file}\"" '3' '4'
		Func_dec_spoon_feed_armored_packets "${Var_enc_parsing_output_file}"
	else
		Func_message "# Func_dec_watch_file running: Func_dec_spoon_feed_armored_packets \"\${Var_enc_parsing_output_file}\"" '3' '4'
		Func_dec_spoon_feed_armored_packets "${Var_enc_parsing_output_file}"
	fi
}
Func_dec_write_script_copy(){
	case "${Var_dec_copy_save_yn}" in
		Y|y|Yes|yes|YES)
			if [ -f "${Var_dec_copy_save_path}" ]; then
				Func_message "# Func_dec_write_script_copy reports script copy already exsists: ${Var_dec_copy_save_path}" '2' '3'
			else
				Func_message "# Func_dec_write_script_copy writing script copy: ${Var_dec_copy_save_path}" '2' '3'
				${Var_cat} > "${Var_dec_copy_save_path}" <<EOF
#!/usr/bin/env bash
Var_script_dir="\${0%/*}"
Var_script_name="\${0##*/}"
Var_enc_parsing_output_file="${Var_enc_parsing_output_file}"
Var_dec_parsing_save_output_yn="${Var_dec_parsing_save_output_yn}"
Var_dec_parsing_output_file="${Var_dec_parsing_output_file}"
Var_dec_pass="${Var_dec_pass}"
Var_dec_search_string="${Var_dec_search_string}"
Var_dec_gpg_opts="${Var_dec_gpg_opts}"
Var_enc_parsing_bulk_out_dir="${Var_enc_parsing_bulk_out_dir}"
Var_dec_parsing_bulk_out_dir="${Var_dec_parsing_bulk_out_dir}"
Var_dec_parsing_disown_yn="${Var_dec_parsing_disown_yn}"
Var_dec_bulk_check_count_max="${Var_dec_bulk_check_count_max}"
Var_dec_bulk_check_sleep="${Var_dec_bulk_check_sleep}"
Var_dev_null="${Var_dev_null}"
Var_dec_pipe_make_yn="${Var_dec_pipe_make_yn}"
Var_dec_pipe_file="${Var_dec_pipe_file}"
Var_dec_pipe_permissions="${Var_dec_pipe_permissions}"
Var_dec_pipe_ownership="${Var_dec_pipe_ownership}"
Var_dec_parsing_quit_string="${Var_dec_parsing_quit_string}"
Func_dec_make_named_pipe(){
	if ! [ -p "\${Var_dec_pipe_file}" ]; then
		${Var_mkfifo} "\${Var_dec_pipe_file}" || exit 1
	fi
	${Var_chmod} "\${Var_dec_pipe_permissions}" "\${Var_dec_pipe_file}" || exit 1
	${Var_chown} "\${Var_dec_pipe_ownership}" "\${Var_dec_pipe_file}" || exit 1
}
Func_dec_pass_the_pass(){
	_pass=( "\$@" )
	if [ -f "\${_pass[@]}" ]; then
		exec 9<"\${_pass[@]}"
	else
		exec 9<(${Var_echo} "\${_pass[@]}")
	fi
}
Func_dec_expand_array_to_block(){
	_input=( "\$@" )
	let _count=0
	until [ "\${_count}" = "\${#_input[@]}" ]; do
		${Var_echo} "\${_input[\${_count}]}"
		let _count++
	done
	unset _count
	unset -v _input[@]
}
Func_dec_do_stuff_with_lines(){
	_enc_block=( "\$@" )
	_enc_input="\$(Func_dec_expand_array_to_block "\${_enc_block[@]}")"
	Func_dec_pass_the_pass "\${Var_dec_pass}"
	if [ -p "\${Var_dec_parsing_output_file}" ]; then
		${Var_cat} <<<"\${_enc_input}" > "\${Var_dec_parsing_output_file}"
	elif [ -f "\${Var_dec_parsing_output_file}" ]; then
		if [ "\${#Var_dec_search_string}" = "0" ]; then
			${Var_cat} <<<"\${_enc_input}" | ${Var_gpg} \${Var_dec_gpg_opts} >> "\${Var_dec_parsing_output_file}"
		else
			${Var_cat} <<<"\${_enc_input}" | ${Var_gpg} \${Var_dec_gpg_opts} | grep "\${Var_dec_search_string}" >> "\${Var_dec_parsing_output_file}"
		fi
	else
		if [ "\${#Var_dec_search_string}" = "0" ]; then
			${Var_cat} <<<"\${_enc_input}" | ${Var_gpg} \${Var_dec_gpg_opts}
		else
			${Var_cat} <<<"\${_enc_input}" | ${Var_gpg} \${Var_dec_gpg_opts} | grep "\${Var_dec_search_string}"
		fi
	fi
	unset -v _enc_block[@]
	unset _enc_input
	exec 9>&-
}
Func_dec_spoon_feed_armored_packets(){
	_input=( "\${@}" )
	_beginning_of_line='-----BEGIN PGP MESSAGE-----'
	_end_of_line='-----END PGP MESSAGE-----'
	if [ -f "\${_input[@]}" ]; then
		mapfile -t _arr_input < "\${_input[@]}"
	elif [ -p "\${_input[@]}" ]; then
		mapfile -t _arr_input < "\${_input[@]}"
	else
		mapfile -t _arr_input <<<"\${_input[@]}"
	fi
	let _count=0
	until [ "\${_count}" = "\${#_arr_input[@]}" ]; do
		if [ "\${Var_dec_parsing_quit_string}" = "\${_arr_input[\${_count}]}" ]; then
			if [ -p "\${Var_enc_parsing_output_file}" ]; then
				${Var_rm} "\${Var_enc_parsing_output_file}"
			fi
			break
		elif [ "\${_end_of_line}" = "\${_arr_input[\${_count}]}" ]; then
			_arr_to_parse+=( "\${_arr_input[\${_count}]}" )
			let _count++
			Func_dec_do_stuff_with_lines "\${_arr_to_parse[@]}"
			unset -v _arr_to_parse[@]
		elif [ "\${_beginning_of_line}" = "\${_arr_input[\${_count}]}" ]; then
			_arr_to_parse=( "\${_arr_input[\${_count}]}" )
			let _count++
		else
			_arr_to_parse+=( "\${_arr_input[\${_count}]}" )
			let _count++
		fi

	done
	unset _count
	unset -v _input[@]
	unset -v _arr_input[@]
}
Func_dec_file_or_dir(){
	_encrypted_path="\${1}"
	Func_dec_pass_the_pass "\${Var_dec_pass}"
	case "\${_encrypted_path}" in
		*.tar.gpg)
			_old_pwd="\${PWD}"
			_output_dir="\${Var_dec_parsing_bulk_out_dir}/\${_encrypted_path##*/}"
			_output_dir="\${_output_dir%.tar.gpg*}"
			if ! [ -d "\${_output_dir}" ]; then
				${Var_mkdir} -p "\${_output_dir}"
				cd "\${_output_dir}"
				${Var_gpg} \${Var_dec_gpg_opts}  "\${_encrypted_path}" | ${Var_tar} -xf -
				cd "\${_old_pwd}"
			fi
			unset _old_pwd
		;;
		*.tgz.gpg)
			_old_pwd="\${PWD}"
			_output_dir="\${Var_dec_parsing_bulk_out_dir}/\${_encrypted_path##*/}"
			_output_dir="\${_output_dir%.tgz.gpg*}"
			if ! [ -d "\${_output_dir}" ]; then
				${Var_mkdir} -p "\${_output_dir}"
				cd "\${_output_dir}"
				${Var_gpg} \${Var_dec_gpg_opts} "\${_encrypted_path}" | ${Var_tar} -xzf -
				cd "\${_old_pwd}"
			fi
			unset _old_pwd
		;;
		*.gpg)
			if ! [ -d "\${Var_dec_parsing_bulk_out_dir}" ]; then
				${Var_mkdir} -p "\${Var_dec_parsing_bulk_out_dir}"
			fi
			_output_file="\${Var_dec_parsing_bulk_out_dir}/\${_encrypted_path##*/}"
			_output_file="\${_output_file%.gpg*}"
			if ! [ -f "\${_output_file}" ]; then
				${Var_cat} "\${_encrypted_path}" | ${Var_gpg} \${Var_dec_gpg_opts} > "\${_output_file}"
				unset _output_file
			fi
		;;
	esac
	exec 9>&-
	unset _encrypted_path
}
Func_dec_watch_bulk_dir(){
	_current_sig=""
	let _watch_count=0
	while [ -d "\${Var_enc_parsing_bulk_out_dir}" ]; do
		_new_sig="\$(find "\${Var_enc_parsing_bulk_out_dir}" -xtype f -print0 | xargs -0 sha1sum | awk '{print \$1}' | sort | sha1sum | awk '{print \$1}')"
		if [ "\${_current_sig}" != "\${_new_sig}" ]; then
			## This funy way of piping into a while loop should silence SheckCheck
			find "\${Var_enc_parsing_bulk_out_dir}" -xtype f | while read _path; do
				Func_dec_file_or_dir "\${_path}"
			done
		fi
		_current_sig="\${_new_sig}"
		let _watch_count++
		if [ "\${Var_dec_bulk_check_count_max}" != "0" ]; then
			if [ "\${_watch_count}" -gt "\${Var_dec_bulk_check_count_max}" ]; then
				unset _watch_count
				break
			fi
		fi
		sleep \${Var_dec_bulk_check_sleep}
	done
}
Func_dec_watch_file(){
	if [ -p "\${Var_enc_parsing_output_file}" ]; then
		while [ -p "\${Var_enc_parsing_output_file}" ]; do
			Func_dec_spoon_feed_armored_packets "\${Var_enc_parsing_output_file}"
			if ! [ -p "\${Var_enc_parsing_output_file}" ]; then
				break
			fi
		done
	elif [ -f "\${Var_enc_parsing_output_file}" ]; then
		Func_dec_spoon_feed_armored_packets "\${Var_enc_parsing_output_file}"
	else
		Func_dec_spoon_feed_armored_packets "\${Var_enc_parsing_output_file}"
	fi
}
Func_assign_arg(){
	_variable="\${1}"
	_value="\${2}"
	declare -g "\${_variable}=\${_value}"
	unset _variable
	unset _value
}
Func_check_args(){
	_arr_input=( "\${@}" )
	let _arr_count=0
	until [ "\${#_arr_input[@]}" = "\${_arr_count}" ]; do
		_arg="\${_arr_input[\${_arr_count}]}"
		case "\${_arg%=*}" in
			--dec-bulk-check-count-max|Var_dec_bulk_check_count_max)
				Func_assign_arg "Var_dec_bulk_check_count_max" "\${_arg#*=}"
			;;
			--dec-bulk-check-sleep|Var_dec_bulk_check_sleep)
				Func_assign_arg "Var_dec_bulk_check_sleep" "\${_arg#*=}"
			;;
			--dec-gpg-opts|Var_dec_gpg_opts)
				Func_assign_arg "Var_dec_gpg_opts" "\${_arg#*=}"
			;;
			--dec-pipe-make-yn|Var_dec_pipe_make_yn)
				Func_assign_arg "Var_dec_pipe_make_yn" "\${_arg#*=}"
			;;
			--dec-pipe-file|Var_dec_pipe_file)
				Func_assign_arg "Var_dec_pipe_file" "\${_arg#*=}"
			;;
			--dec-pipe-permissions|Var_dec_pipe_permissions)
				Func_assign_arg "Var_dec_pipe_permissions" "\${_arg#*=}"
			;;
			--dec-pipe-ownership|Var_dec_pipe_ownership)
				Func_assign_arg "Var_dec_pipe_ownership" "\${_arg#*=}"
			;;
			--dec-parsing-save-output-yn|Var_dec_parsing_save_output_yn)
				Func_assign_arg "Var_dec_parsing_save_output_yn" "\${_arg#*=}"
			;;
			--dec-parsing-output-file|Var_dec_parsing_output_file)
				Func_assign_arg "Var_dec_parsing_output_file" "\${_arg#*=}"
			;;
			--dec-parsing-disown-yn|Var_dec_parsing_disown_yn)
				Func_assign_arg "Var_dec_parsing_disown_yn" "\${_arg#*=}"
			;;
			--dec-pass|Var_dec_pass)
				Func_assign_arg "Var_dec_pass" "\${_arg#*=}"
			;;
			--dec-search-string|Var_dec_search_string)
				Func_assign_arg "Var_dec_search_string" "\${_arg#*=}"
			;;
			--enc-parsing-output-file|Var_enc_parsing_output_file)
				Func_assign_arg "Var_enc_parsing_output_file" "\${_arg#*=}"
			;;
			--enc-parsing-bulk-out-dir|Var_enc_parsing_bulk_out_dir)
				Func_assign_arg "Var_enc_parsing_bulk_out_dir" "\${_arg#*=}"
			;;
			--dec-parsing-bulk-out-dir|Var_dec_parsing_bulk_out_dir)
				Func_assign_arg "Var_dec_parsing_bulk_out_dir" "\${_arg#*=}"
			;;
			--dec-parsing-quit-string|Var_dec_parsing_quit_string)
				Func_assign_arg "Var_dec_parsing_quit_string" "\${_arg#*=}"
			;;
			--source-var-file|Var_source_var_file)
				Func_assign_arg "Var_source_var_file" "\${_arg#*=}"
				if [ -f "\${Var_source_var_file}" ]; then
					source "\${Var_source_var_file}"
				fi
			;;
			---*)
				_extra_var="\${_arg%=*}"
				_extra_arg="\${_arg#*=}"
				Func_assign_arg "\${_extra_var/---/}" "\${_extra_arg}"
			;;
			*)
				declare -ag "Arr_extra_input+=( \${_arg} )"
			;;
		esac
		let _arr_count++
	done
	unset _arr_count
}
Func_main(){
	_input=( "\$@" )
	if [ "\${#_input[@]}" != "0" ]; then
		Func_check_args "\${_input[@]}"
	fi
	case "\${Var_dec_pipe_make_yn}" in
		y|Y|yes|Yes)
			Func_dec_make_named_pipe
		;;
	esac
	case "\${Var_dec_parsing_save_output_yn}" in
		y|Y|yes|Yes)
			if ! [ -f "\${Var_dec_parsing_output_file}" ]; then
				${Var_touch} "\${Var_dec_parsing_output_file}"
			fi
		;;
	esac
	case "\${Var_dec_parsing_disown_yn}" in
		Y|y|Yes|yes|YES)
			Func_dec_watch_file >"\${Var_dev_null}" 2>&1 &
			PID_loop=\$!
			disown "\${PID_loop}"
			Func_dec_watch_bulk_dir >"\${Var_dev_null}" 2>&1 &
			PID_loop=\$!
			disown "\${PID_loop}"
			if [ "\${#Arr_extra_input[@]}" != "0" ] && [ -p "\${Var_dec_pipe_file}" ]; then
				${Var_cat} <<<"\${Arr_extra_input[*]}" > "\${Var_dec_pipe_file}"
			fi
		;;
		*)
			Func_dec_watch_file
			Func_dec_watch_bulk_dir
		;;
	esac
}
Func_main "\${@}"
${Var_echo} "## \${Var_script_name} exited with \$? at \$(date)"

EOF

				Func_message "# Func_dec_write_script_copy running: Func_set_owner_permissions \"${Var_dec_copy_save_permissions}\" \"${Var_dec_copy_save_ownership}\" \"${Var_dec_copy_save_path}\"" '2' '3'
				Func_set_owner_permissions "${Var_dec_copy_save_permissions}" "${Var_dec_copy_save_ownership}" "${Var_dec_copy_save_path}"
			fi
		;;
		*)
			Func_message "# Func_dec_write_script_copy skipping writing of: ${Var_dec_copy_save_path}" '2' '3'
		;;
	esac

}
## Call main function to get things started...
Func_message "# ${Var_script_name} running: Func_main \"\$@\"" '0' '1'
Func_main "$@"
Func_message "# ${Var_script_dir}/${Var_script_name} finished at: $(date)" '0' '1'

#		

