#!/usr/bin/env bash
##shellcheck -e SC2002,SC2004,SC2086,SC2129 Paranoid_WiFi.sh
Var_script_dir="${0%/*}"
Var_script_name="${0##*/}"
## Internal script variables that can also be set by users
Var_debug_level="0"
Var_log_level="0"
Var_script_log_path="${PWD}/${Var_script_name%.sh*}.log"
Var_columns="${COLUMNS:-$(tput cols)}"
Var_columns="${Var_columns:-80}"
Var_authors_contact='strangerthanbland@gmail.com'
Var_authors_username='S0AndS0'
Var_source_var_file=""
Var_script_version_main="0"
Var_script_version_sub="1"
Var_script_version_full="${Var_script_version_main}.${Var_script_version_sub}"
## Variables for apt-get
Var_apt_check_depends_yn=""
Var_apt_depends_list="openvpn,easy-rsa"
## Variables for OpenVPN server configs
Var_ovpns_config_yn=""
Var_ovpns_auto_start_yn=""
Var_ovpns_config_path="/etc/openvpn/server.conf"
Var_ovpns_internal_ip="10.8.0.0"
Var_ovpns_internal_netmask="255.255.255.0"
Var_ovpns_listen_ip="$(ip addr | awk '/inet/{print $2}' | grep -vE '127' | awk '{gsub("/"," "); print $1}' | head -n1)"
Var_ovpns_listen_port="9988"
Var_ovpns_chroot_yn=""
Var_ovpns_chroot_path="/etc/openvpn/jailed_server"
Var_ovpns_dns_ip_list="208.67.222.222,208.67.220.220"
Var_ovpns_push_route_yn=""
Var_ovpns_client_to_client_yn=""
Var_ovpns_route_ip=""
Var_ovpns_route_netmask=""
Var_ovpns_user="vpnjail"
Var_ovpns_group="nogroup"
Var_ovpns_ca_path="/etc/openvpn/certs/ca.crt"
Var_ovpns_cert_path="/etc/openvpn/certs/server.crt"
Var_ovpns_key_path="/etc/openvpn/certs/server.key"
Var_ovpns_dh_path="/etc/openvpn/certs/dh2048.pem"
Var_ovpns_ipp_path="/etc/openvpn/ipp.txt"
Var_ovpns_ta_path="/etc/openvpn/certs/ta.key"
Var_ovpns_status_path="/etc/openvpn/openvpn-status.log"
Var_ovpns_log_path="/etc/openvpn/openvpn.log"
Var_ovpns_verbosity="3"
Var_ovpn_cipher="AES-256-CBC"
Var_ovpn_auth="SHA512"
Var_ovpns_sndbuf="393216"
Var_ovpns_rcvbuf="393216"
Var_ovpns_tun_mtu="1400"
Var_ovpns_mssfix="1360"
Var_ovpn_tls_cipher="TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-256-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA:TLS-DHE-RSA-WITH-AES-128-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA"
## Easy-RSA config settings
Var_easyrsa_working_path="/etc/openvpn/easy-rsa"
Var_easyrsa_server_name="server"
Var_easyrsa_key_size="2048"
Var_easyrsa_ca_expire="3650"
Var_easyrsa_key_expire="3650"
Var_easyrsa_key_country="NC"
Var_easyrsa_key_province="NP"
Var_easyrsa_key_city="NC"
Var_easyrsa_key_org="Org"
Var_easyrsa_key_email="$(id -un)@${HOSTNAME}.local"
Var_easyrsa_key_ou="OU"
Var_easyrsa_key_name="EasyRSA"
## Variables for OpenVPN client configs
Var_ovpnc_config_yn=""
Var_ovpnc_verbosity="3"
Var_ovpnc_config_dir="${PWD}/OVPNC_configs"
Var_ovpnc_names=""
Var_ovpnc_win32_tap=""
Var_ovpnc_hosts_ports="$(dig +short myip.opendns.com @resolver1.opendns.com):${Var_ovpns_listen_port}"
Var_ovpnc_http_proxies_ports=""
Var_ovpnc_pass_yn=""
Var_ovpnc_pass_length="32"
## Variables shared by OpenVPN client and server configs
Var_ovpn_protocal="udp"
Var_ovpn_tun_or_tap="tun"
## Variables for iptables
Var_iptables_write_config_yn=""
Var_iptables_config_path="/etc/openvpn/iptables/${Var_easyrsa_server_name}.sh"
## Variables for executables
Var_echo_exec_path="$(which echo)"
## Assigne default functions for handling messages,
Func_check_args(){
	_arr_input=( "${@}" )
	Func_message "# ${Var_script_name} parsing: ${_arr_input[*]}" '2' '3'
	let _arr_count=0
	until [ "${#_arr_input[@]}" = "${_arr_count}" ]; do
		_arg="${_arr_input[${_arr_count}]}"
		case "${_arg%=*}" in
			#--|)
			#	Func_assign_arg "" "${_arg#*=}"
			#;;
			--apt-check-depends-yn|Var_apt_check_depends_yn)
				Func_assign_arg "Var_apt_check_depends_yn" "${_arg#*=}"
			;;
			--apt-depends-list|Var_apt_depends_list)
				Func_assign_arg "Var_apt_depends_list" "${_arg#*=}"
			;;
			--debug-level|Var_debug_level)
				Func_assign_arg "Var_debug_level" "${_arg#*=}"
			;;
			--easyrsa-working-path|Var_easyrsa_working_path)
				Func_assign_arg "Var_easyrsa_working_path" "${_arg#*=}"
			;;
			--easyrsa-server-name|Var_easyrsa_server_name)
				Func_assign_arg "Var_easyrsa_server_name" "${_arg#*=}"
			;;
			--easyrsa-key-size|Var_easyrsa_key_size)
				Func_assign_arg "Var_easyrsa_key_size" "${_arg#*=}"
			;;
			--easyrsa-ca-expire|Var_easyrsa_ca_expire)
				Func_assign_arg "Var_easyrsa_ca_expire" "${_arg#*=}"
			;;
			--easyrsa-key-expire|Var_easyrsa_key_expire)
				Func_assign_arg "Var_easyrsa_key_expire" "${_arg#*=}"
			;;
			--easyrsa-key-country|Var_easyrsa_key_country)
				Func_assign_arg "Var_easyrsa_key_country" "${_arg#*=}"
			;;
			--easyrsa-key-province|Var_easyrsa_key_province)
				Func_assign_arg "Var_easyrsa_key_province" "${_arg#*=}"
			;;
			--easyrsa-key-city|Var_easyrsa_key_city)
				Func_assign_arg "Var_easyrsa_key_city" "${_arg#*=}"
			;;
			--easyrsa-key-org|Var_easyrsa_key_org)
				Func_assign_arg "Var_easyrsa_key_org" "${_arg#*=}"
			;;
			--easyrsa-key-email|Var_easyrsa_key_email)
				Func_assign_arg "Var_easyrsa_key_email" "${_arg#*=}"
			;;
			--easyrsa-key-ou|Var_easyrsa_key_ou)
				Func_assign_arg "Var_easyrsa_key_ou" "${_arg#*=}"
			;;
			--easyrsa-key-name|Var_easyrsa_key_name)
				Func_assign_arg "Var_easyrsa_key_name" "${_arg#*=}"
			;;
			--iptables-write-config-yn|Var_iptables_write_config_yn)
				Func_assign_arg "Var_iptables_write_config_yn" "${_arg#*=}"
			;;
			--iptables-config-path|Var_iptables_config_path)
				Func_assign_arg "Var_iptables_config_path" "${_arg#*=}"
			;;
			--log-level|Var_log_level)
				Func_assign_arg "Var_log_level" "${_arg#*=}"
			;;
			--ovpn-tls-cipher|Var_ovpn_tls_cipher)
				Func_assign_arg "Var_ovpn_tls_cipher" "${_arg#*=}"
			;;
			--ovpn-listen-protocal|Var_ovpn_protocal)
				Func_assign_arg "Var_ovpn_protocal" "${_arg#*=}"
			;;
			--ovpn-tun-or-tap|Var_ovpn_tun_or_tap)
				Func_assign_arg "Var_ovpn_tun_or_tap" "${_arg#*=}"
			;;
			--ovpnc-config-yn|Var_ovpnc_config_yn)
				Func_assign_arg "Var_ovpnc_config_yn" "${_arg#*=}"
			;;
			--ovpnc-verbosity|Var_ovpnc_verbosity)
				Func_assign_arg "Var_ovpnc_verbosity" "${_arg#*=}"
			;;
			--ovpnc-config-dir|Var_ovpnc_config_dir)
				Func_assign_arg "Var_ovpnc_config_dir" "${_arg#*=}"
			;;
			--ovpnc-names|Var_ovpnc_names)
				Func_assign_arg "Var_ovpnc_names" "${_arg#*=}"
			;;
			--ovpnc-win32-tap|Var_ovpnc_win32_tap)
				Func_assign_arg "Var_ovpnc_win32_tap" "${_arg#*=}"
			;;
			--ovpnc-hosts-ports|Var_ovpnc_hosts_ports)
				Func_assign_arg "Var_ovpnc_hosts_ports" "${_arg#*=}"
			;;
			--ovpnc-http-proxies-ports|Var_ovpnc_http_proxies_ports)
				Func_assign_arg "Var_ovpnc_http_proxies_ports" "${_arg#*=}"
			;;
			--ovpnc-pass-yn|Var_ovpnc_pass_yn)
				Func_assign_arg "Var_ovpnc_pass_yn" "${_arg#*=}"
			;;
			--ovpnc-pass-length|Var_ovpnc_pass_length)
				Func_assign_arg "Var_ovpnc_pass_length" "${_arg#*=}"
			;;
			--ovpns-push-route-yn|Var_ovpns_push_route_yn)
				Func_assign_arg "Var_ovpns_push_route_yn" "${_arg#*=}"
			;;
			--ovpns-client-to-client-yn|Var_ovpns_client_to_client_yn)
				Func_assign_arg "Var_ovpns_client_to_client_yn" "${_arg#*=}"
			;;
			--ovpns-config-yn|Var_ovpns_config_yn)
				Func_assign_arg "Var_ovpns_config_yn" "${_arg#*=}"
			;;
			--ovpns-auto-start-yn|Var_ovpns_auto_start_yn)
				Func_assign_arg "Var_ovpns_auto_start_yn" "${_arg#*=}"
			;;
			--ovpns-config-path|Var_ovpns_config_path)
				Func_assign_arg "Var_ovpns_config_path" "${_arg#*=}"
			;;
			--ovpns-chroot-yn|Var_ovpns_chroot_yn)
				Func_assign_arg "Var_ovpns_chroot_yn" "${_arg#*=}"
			;;
			--ovpns-chroot-path|Var_ovpns_chroot_path)
				Func_assign_arg "Var_ovpns_chroot_path" "${_arg#*=}"
			;;
			--ovpns-dns-ip-list|Var_ovpns_dns_ip_list)
				Func_assign_arg "Var_ovpns_dns_ip_list" "${_arg#*=}"
			;;
			--ovpns-internal-ip|Var_ovpns_internal_ip)
				Func_assign_arg "Var_ovpns_internal_ip" "${_arg#*=}"
			;;
			--ovpns-internal-netmask|Var_ovpns_internal_netmask)
				Func_assign_arg "Var_ovpns_internal_netmask" "${_arg#*=}"
			;;
			--ovpns-listen-ip|Var_ovpns_listen_ip)
				Func_assign_arg "Var_ovpns_listen_ip" "${_arg#*=}"
			;;
			--ovpns-listen-port|Var_ovpns_listen_port)
				Func_assign_arg "Var_ovpns_listen_port" "${_arg#*=}"
			;;
			--ovpns-route-ip|Var_ovpns_route_ip)
				Func_assign_arg "Var_ovpns_route_ip" "${_arg#*=}"
			;;
			--ovpns-route-netmask|Var_ovpns_route_netmask)
				Func_assign_arg "Var_ovpns_route_netmask" "${_arg#*=}"
			;;
			--ovpns-user|Var_ovpns_user)
				Func_assign_arg "Var_ovpns_user" "${_arg#*=}"
			;;
			--ovpns-group|Var_ovpns_group)
				Func_assign_arg "Var_ovpns_group" "${_arg#*=}"
			;;
			--ovpns-ca-path|Var_ovpns_ca_path)
				Func_assign_arg "Var_ovpns_ca_path" "${_arg#*=}"
			;;
			--ovnps-cert-path|Var_ovpns_cert_path)
				Func_assign_arg "Var_ovpns_cert_path" "${_arg#*=}"
			;;
			--ovpns-key-path|Var_ovpns_key_path)
				Func_assign_arg "Var_ovpns_key_path" "${_arg#*=}"
			;;
			--ovpns-dh-path|Var_ovpns_dh_path)
				Func_assign_arg "Var_ovpns_dh_path" "${_arg#*=}"
			;;
			--ovpns-ipp-path|Var_ovpns_ipp_path)
				Func_assign_arg "Var_ovpns_ipp_path" "${_arg#*=}"
			;;
			--ovpns-status-path|Var_ovpns_status_path)
				Func_assign_arg "Var_ovpns_status_path" "${_arg#*=}"
			;;
			--ovpns-log-path|Var_ovpns_log_path)
				Func_assign_arg "Var_ovpns_log_path" "${_arg#*=}"
			;;
			--ovpns-ta-path|Var_ovpns_ta_path)
				Func_assign_arg "Var_ovpns_ta_path" "${_arg#*=}"
			;;
			--ovpns-verbosity|Var_ovpns_verbosity)
				Func_assign_arg "Var_ovpns_verbosity" "${_arg#*=}"
			;;
			--ovpns-cipher|Var_ovpn_cipher)
				Func_assign_arg "Var_ovpn_cipher" "${_arg#*=}"
			;;
			--ovpns-auth|Var_ovpn_auth)
				Func_assign_arg "Var_ovpn_auth" "${_arg#*=}"
			;;
			--ovpns-sndbuf|Var_ovpns_sndbuf)
				Func_assign_arg "Var_ovpns_sndbuf" "${_arg#*=}"
			;;
			--ovpns-rcvbuf|Var_ovpns_rcvbuf)
				Func_assign_arg "Var_ovpns_rcvbuf" "${_arg#*=}"
			;;
			--ovpns-tun-mtu|Var_ovpns_tun_mtu)
				Func_assign_arg "Var_ovpns_tun_mtu" "${_arg#*=}"
			;;
			--ovpns-mssfix|Var_ovpns_mssfix)
				Func_assign_arg "Var_ovpns_mssfix" "${_arg#*=}"
			;;
			--script-log-path|Var_script_log_path)
				Func_assign_arg "Var_script_log_path" "${_arg#*=}"
			;;
			--columns|Var_columns)
				Func_assign_arg "Var_columns" "${_arg#*=}"
			;;
			--save-variables-yn|Var_save_variables_yn)
				Func_assign_arg "Var_save_variables_yn" "${_arg#*=}"
			;;
			--source-var-file|Var_source_var_file)
				Func_assign_arg "Var_source_var_file" "${_arg#*=}"
				if [ -f "${Var_source_var_file}" ]; then
					Func_message "# ${Var_script_name} running: source \"${Var_source_var_file}\"" '2' '3'
					source "${Var_source_var_file}"
				fi
			;;
			---*)
				_extra_var="${_arg%=*}"
				_extra_arg="${_arg#*=}"
				Func_assign_arg "${_extra_var/---/}" "${_extra_arg}"
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
			--version)
				echo "# ${Var_script_name} version: ${Var_script_version_full}"
				exit 0
			;;
			*)
				Func_message "# " '2' '3'
				declare -ag "Arr_extra_input+=( ${_arg} )"
			;;
		esac
		let _arr_count++
	done
	unset _arr_count
}
## Display what current values are held by command line options
Func_help(){
	echo "# ${Var_script_dir}/${Var_script_name} knows the following command line options"
	echo "# --columns		Var_columns=\"${Var_columns}\""
	echo "# --debug-level		Var_debug_level=\"${Var_debug_level}\""
	echo "# --log-level		Var_log_level=\"${Var_log_level}\""
	echo "# --script-log-level	Var_script_log_path=\"${Var_script_log_path}\""
	echo "# --save-variables-yn	Var_save_variables_yn=\"${Var_save_variables_yn}\""
	echo "# --source-var-file	Var_source_var_file=\"${Var_source_var_file}\""
	echo "# --license		Display the license for this script."
	echo "# --help			Display this message."
	echo "# --version		Display version for this script."
	echo "## Command line options for apt-get automation"
	echo "# --apt-check-depends-yn		Var_apt_check_depends_yn=\"${Var_apt_check_depends_yn}\""
	echo "# --apt-depends-list		Var_apt_depends_list=\"${Var_apt_depends_list}\""
	echo "# --iptables-write-config-yn	Var_iptables_write_config_yn=\"${Var_iptables_write_config_yn}\""
	echo "# --iptables-config-path		Var_iptables_config_path=\"${Var_iptables_config_path}\""
	echo "## Command line options for OpenVPN server/client installation/configuration"
	echo "# --ovpn-auth			Var_ovpn_auth=\"${Var_ovpn_auth}\""
	echo "# --ovpn-cipher			Var_ovpn_cipher=\"${Var_ovpn_cipher}\""
	echo "# --ovpn-protocal			Var_ovpn_protocal=\"${Var_ovpn_protocal}\""
	echo "# --ovpn-tun-or-tap		Var_ovpn_tun_or_tap=\"${Var_ovpn_tun_or_tap}\""
	echo "## Command line options for OpenVPN client configuration"
	echo "# --ovpnc-config-yn		Var_ovpnc_config_yn=\"${Var_ovpnc_config_yn}\""
	echo "# --ovpnc-config-dir		Var_ovpnc_config_dir=\"${Var_ovpnc_config_dir}\""
	echo "# --ovpnc-names			Var_ovpnc_names=\"${Var_ovpnc_names}\""
	echo "# --ovpnc-win32-tap		Var_ovpnc_win32_tap=\"${Var_ovpnc_win32_tap}\""
	echo "# --ovpnc-hosts-ports		Var_ovpnc_hosts_ports=\"${Var_ovpnc_hosts_ports}\""
	echo "# --ovpnc-http-proxies-ports	Var_ovpnc_http_proxies_ports=\"${Var_ovpnc_http_proxies_ports}\""
	echo "# --ovpnc-pass-yn			Var_ovpnc_pass_yn=\"${Var_ovpnc_pass_yn}\""
	echo "# --ovpnc-pass-length		Var_ovpnc_pass_length=\"${Var_ovpnc_pass_length}\""
	echo "# --ovpnc-push-route-yn		Var_ovpns_push_route_yn=\"${Var_ovpns_push_route_yn}\""
	echo "## Command line options for OpenVPN server installation/configuration"
	echo "# --ovnps-config-yn		Var_ovpns_config_yn=\"${Var_ovpns_config_yn}\""
	echo "# --ovpns-auto-start-yn		Var_ovpns_auto_start_yn=\"${Var_ovpns_auto_start_yn}\""
	echo "# --ovpns-client-to-client-yn	Var_ovpns_client_to_client_yn=\"${Var_ovpns_client_to_client_yn}\""
	echo "# --ovpns-config-path		Var_ovpns_config_path=\"${Var_ovpns_config_path}\""
	echo "# --ovpns-chroot-yn		Var_ovpns_chroot_yn=\"${Var_ovpns_chroot_yn}\""
	echo "# --ovpns-chroot-path		Var_ovpns_chroot_path=\"${Var_ovpns_chroot_path}\""
	echo "# --ovpns-dns-ip-list		Var_ovpns_dns_ip_list=\"${Var_ovpns_dns_ip_list}\""
	echo "# --ovpns-internal-ip		Var_ovpns_internal_ip=\"${Var_ovpns_internal_ip}\""
	echo "# --ovpns-internal-netmask	Var_ovpns_internal_netmask=\"${Var_ovpns_internal_netmask}\""
	echo "# --ovpns-listen-ip		Var_ovpns_listen_ip=\"${Var_ovpns_listen_ip}\""
	echo "# --ovpns-listen-port		Var_ovpns_listen_port=\"${Var_ovpns_listen_port}\""
	echo "# --ovpns-route-ip		Var_ovpns_route_ip=\"${Var_ovpns_route_ip}\""
	echo "# --ovpns-route-netmask		Var_ovpns_route_netmask=\"${Var_ovpns_route_netmask}\""
	echo "# --ovpns-user			Var_ovpns_user=\"${Var_ovpns_user}\""
	echo "# --ovpns-group			Var_ovpns_group=\"${Var_ovpns_group}\""
	echo "# --ovpns-ca-path			Var_ovpns_ca_path=\"${Var_ovpns_ca_path}\""
	echo "# --ovpns-cert-path		Var_ovpns_cert_path=\"${Var_ovpns_cert_path}\""
	echo "# --ovpns-key-path		Var_ovpns_key_path=\"${Var_ovpns_key_path}\""
	echo "# --ovpns-dh-path			Var_ovpns_dh_path=\"${Var_ovpns_dh_path}\""
	echo "# --ovpns-ipp-path		Var_ovpns_ipp_path=\"${Var_ovpns_ipp_path}\""
	echo "# --ovpns-status-path		Var_ovpns_status_path=\"${Var_ovpns_status_path}\""
	echo "# --ovpns-log-path		Var_ovpns_log_path=\"${Var_ovpns_log_path}\""
	echo "# --ovpns-verbosity		Var_ovpns_verbosity=\"${Var_ovpns_verbosity}\""
	echo "# --ovpns-tun-mtu			Var_ovpns_tun_mtu=\"${Var_ovpns_tun_mtu}\""
	echo "# --ovpns-mssfix			Var_ovpns_mssfix=\"${Var_ovpns_mssfix}\""
	echo "# --ovpns-ta-path			Var_ovpns_ta_path=\"${Var_ovpns_ta_path}\""
	echo "# --ovpn-tls-cipher		Var_ovpn_tls_cipher=\"${Var_ovpn_tls_cipher}\""
	echo "# --easyrsa-working-path		Var_easyrsa_working_path=\"${Var_easyrsa_working_path}\""
	echo "# --easyrsa-server-name		Var_easyrsa_server_name=\"${Var_easyrsa_server_name}\""
	echo "# --easyrsa-key-size		Var_easyrsa_key_size=\"${Var_easyrsa_key_size}\""
	echo "# --easyrsa-ca-expire		Var_easyrsa_ca_expire=\"${Var_easyrsa_ca_expire}\""
	echo "# --easyrsa-key-expire		Var_easyrsa_key_expire=\"${Var_easyrsa_key_expire}\""
	echo "# --easyrsa-key-country		Var_easyrsa_key_country=\"${Var_easyrsa_key_country}\""
	echo "# --easyrsa-key-province		Var_easyrsa_key_province=\"${Var_easyrsa_key_province}\""
	echo "# --easyrsa-key-city		Var_easyrsa_key_city=\"${Var_easyrsa_key_city}\""
	echo "# --easyrsa-key-org		Var_easyrsa_key_org=\"${Var_easyrsa_key_org}\""
	echo "# --easyrsa-key-email		Var_easyrsa_key_email=\"${Var_easyrsa_key_email}\""
	echo "# --easyrsa-key-ou		Var_easyrsa_key_ou=\"${Var_easyrsa_key_ou}\""
	echo "# --easyrsa-key-name		Var_easyrsa_key_name=\"${Var_easyrsa_key_name}\""
}
## Note the following three functions should not need much editing
Func_script_license_customizer(){
	Func_message "## Salutations ${Var_script_current_user}, the following license" '0' '42'
	Func_message "#  only applies to this script [${Var_script_title}]. Software external to but" '0' '42'
	Func_message "#  used by [${Var_script_name}] are protected under their own licensing" '0' '42'
	Func_message "#  usage agreements. The authors of this project assume **no** rights" '0' '42'
	Func_message "#  to modify software licensing agreements external to [${Var_script_name}]" '0' '42'
	Func_message '## GNU AGPL v3 Notice start' '0' '42'
	Func_message "# ${Var_script_name}, configurer/manager for chroot jailed OpenVPN servers." '0' '42'
	Func_message "#  Copyright (C) 2016 ${Var_authors_username}" '0' '42'
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
			fold -sw $((${Var_columns_width}-8)) "${_responce}/Licenses/GNU_AGPLv3_Code.md" | less -R5
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
			_folded_message="$(fold -sw $((${Var_columns}-6)) <<<"${_message}" | sed -e "s/^.*$/$(echo -n "#DBL-${_debug_level}") &/g")"
			cat <<<"${_folded_message}"
		fi
	fi
	if [ "${#_message}" != "0" ]; then
		if [ "${Var_log_level}" -gt "${_log_level}" ]; then
			cat <<<"${_message}" >> "${Var_script_log_path}"
		fi
	fi
}
Func_assign_arg(){
	_variable="${1}"
	_value="${2}"
	Func_message "# ${Var_script_name} running: declare -g \"${_variable}=${_value}\"" '3' '4'
	Func_message "# Func_assign_arg running: declare -g \"${_variable}=${_value}\"" '3' '4'
	declare -g "${_variable}=${_value}"
	Func_save_variables "${_variable}" "${_value}"
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
## Functions to do stuff with assigned variables
Func_apt_check_install_depends(){
	Func_message "# Func_apt_check_install_depends running: apt-get update -qqq" '2' '3'
	apt-get update -qqq
	for _app in ${Var_apt_depends_list//,/ }; do
		Func_message "# Func_apt_check_install_depends checking [${_app}] installation status" '2' '3'
		_installed_state="$(apt-cache policy ${_app} | awk '/Installed/{print $2}')"
		case "${_installed_state}" in
			*none*)
				Func_message "# Func_apt_check_install_depends found [${_app}] to install" '2' '3'
				declare -a "Arr_apt_depends_list+=( ${_app} )"
			;;
		esac
	done
	if [ "${#Arr_apt_depends_list[@]}" != "0" ]; then
		Func_message "# Func_apt_check_install_depends installing [${Arr_apt_depends_list[*]}] via apt-get" '2' '3'
		apt-get install -qqqy ${Arr_apt_depends_list[*]}
	fi
}
Func_write_openvpn_server_config(){
	if ! [ -d "${Var_ovpns_config_path%/*}" ]; then
		Func_message "# Func_write_openvpn_server_config running: mkdir -p \"${Var_ovpns_config_path%/*}\" \"${Var_ovpns_config_path%.conf*}.bak\"" '2' '3'
		mkdir -p "${Var_ovpns_config_path%/*}"
	fi
	if [ -f "${Var_ovpns_config_path}" ]; then
		Func_message "# Func_write_openvpn_server_config running: mv -v \"${Var_ovpns_config_path}\" \"${Var_ovpns_config_path%.conf*}.bak\"" '2' '3'
		mv -v "${Var_ovpns_config_path}" "${Var_ovpns_config_path%.conf*}.bak"
	fi
	Func_message "# Func_write_openvpn_server_config beguining server configs: ${Var_ovpns_config_path}" '2' '3'
	cat > "${Var_ovpns_config_path}" <<EOF
dev ${Var_ovpn_tun_or_tap:-tun}
local ${Var_ovpns_listen_ip}
port ${Var_ovpns_listen_port}
proto ${Var_ovpn_protocal}
server ${Var_ovpns_internal_ip} ${Var_ovpns_internal_netmask}
keepalive 10 60
comp-lzo
persist-key
persist-tun
EOF
	case "${Var_ovpns_client_to_client_yn}" in
		y|Y|yes|Yes|YES)
			Func_message "# Func_write_openvpn_server_config enabling client to client configs: ${Var_ovpns_config_path}" '2' '3'
			cat >> "${Var_ovpns_config_path}" <<EOF
client-to-client
EOF
		;;
	esac
	case "${Var_ovpns_chroot_yn}" in
		y|Y|yes|Yes|YES)
			Func_message "# Func_write_openvpn_server_config running: mkdir -p \"${Var_ovpns_chroot_path}/dev/log\"" '2' '3'
			mkdir -p "${Var_ovpns_chroot_path}/dev/log"
			Func_message "# Func_write_openvpn_server_config running: mkdir -p \"${Var_ovpns_chroot_path}/tmp\"" '2' '3'
			mkdir -p "${Var_ovpns_chroot_path}/tmp"
			Func_message "# Func_write_openvpn_server_config enabling chroot configs: ${Var_ovpns_config_path}" '2' '3'
			cat >> "${Var_ovpns_config_path}" <<EOF
chroot ${Var_ovpns_chroot_path}
EOF
			Func_message "# Func_write_openvpn_server_config running: echo \"\$AddUnixListenSocket ${Var_ovpns_chroot_path}/dev/log\" >> \"/etc/rsyslog.conf\"" '2' '3'
			echo "\$AddUnixListenSocket ${Var_ovpns_chroot_path}/dev/log" >> "/etc/rsyslog.conf"
			Func_message "# Func_write_openvpn_server_config running: service rsyslog restart" '2' '3'
			service rsyslog restart
		;;
	esac
	Func_message "# Func_write_openvpn_server_config writing key and certs to: ${Var_ovpns_config_path}" '2' '3'
	cat >> "${Var_ovpns_config_path}" <<EOF
user ${Var_ovpns_user}
group ${Var_ovpns_group}
ca ${Var_ovpns_ca_path}
cert ${Var_ovpns_cert_path}
key ${Var_ovpns_key_path}
dh ${Var_ovpns_dh_path}
ifconfig-pool-persist ${Var_ovpns_ipp_path} 0
status ${Var_ovpns_status_path}
log ${Var_ovpns_log_path}
verb ${Var_ovpns_verbosity}
push "redirect-gateway def1"
EOF
	for _dns_ip in ${Var_ovpns_dns_ip_list//,/ }; do
		Func_message "# Func_write_openvpn_server_config writing push dns [${_dns_ip}] config to: ${Var_ovpns_config_path}" '2' '3'
		cat >> "${Var_ovpns_config_path}" <<EOF
push "dhcp-option DNS ${_dns_ip}"
EOF
	done
	case "${Var_ovpns_push_route_yn}" in
		y|Y|yes|Yes|YES)
			Func_message "# Func_write_openvpn_server_config writing push route [${Var_ovpns_route_ip} ${Var_ovpns_route_netmask}] config to: ${Var_ovpns_config_path}" '2' '3'
			cat >> "${Var_ovpns_config_path}" <<EOF
push "route ${Var_ovpns_route_ip} ${Var_ovpns_route_netmask}"
EOF
		;;
	esac
	Func_message "# Func_write_openvpn_server_config writing last few configs to: ${Var_ovpns_config_path}" '2' '3'
	cat >> "${Var_ovpns_config_path}" <<EOF
route ${Var_ovpns_route_ip} ${Var_ovpns_route_netmask}
cipher ${Var_ovpn_cipher}
auth ${Var_ovpn_auth}
tls-cipher ${Var_ovpn_tls_cipher}
tls-auth ${Var_ovpns_ta_path} 0
sndbuf ${Var_ovpns_sndbuf}
rcvbuf ${Var_ovpns_rcvbuf}
push "sndbuf ${Var_ovpns_sndbuf}"
push "rcvbuf ${Var_ovpns_rcvbuf}"
tun-mtu ${Var_ovpns_tun_mtu}
mssfix ${Var_ovpns_mssfix}
#push "dhcp-option PROXY_HTTP <ip> <port>"
#push "dhcp-option PROXY_HTTPS <ip> <port>"
push "block-outside-dns"
EOF
	case "${Var_ovpns_auto_start_yn}" in
		y|Y|yes|Yes|YES)
			Func_message "# Func_write_openvpn_server_config running: service openvpn restart" '2' '3'
			service openvpn restart
			Func_message "# Func_write_openvpn_server_config reports: $(netstat -plantu | grep -E "${Var_ovpns_listen_port}")" '2' '3'
		;;
	esac
}
Func_make_or_copy_easy_rsa_examples(){
	Func_message "# Func_make_or_copy_easy_rsa_examples running: $(which make-cadir) \"${Var_easyrsa_working_path}\"" '3' '4'
	$(which make-cadir) "${Var_easyrsa_working_path}"
	if [ "$?" != "0" ]; then
		Func_message "# Func_make_or_copy_easy_rsa_examples failed to generate ca dir [${Var_easyrsa_working_path}] with [$(which make-cadir)] command" '3' '4'
		if ! [ -d "${Var_easyrsa_working_path}" ]; then
			mkdir -p "${Var_easyrsa_working_path}"
		fi
		if [ -d "/usr/share/easy-rsa" ]; then
			Func_message "# Func_make_or_copy_easy_rsa_examples running: cp -R \"/usr/share/easy-rsa/*\" \"${Var_easyrsa_working_path}\"" '3' '4'
			cp -R "/usr/share/easy-rsa/*" "${Var_easyrsa_working_path}"
		elif [ -d "/usr/share/doc/openvpn/examples/easy-rsa/2.0" ]; then
			Func_message "# Func_make_or_copy_easy_rsa_examples running: cp -R \"/usr/share/doc/openvpn/examples/easy-rsa/2.0/*\" \"${Var_easyrsa_working_path}\"" '3' '4'
			cp -R "/usr/share/doc/openvpn/examples/easy-rsa/2.0/*" "${Var_easyrsa_working_path}"
## Add other directory matching if easy-rsa examples live elsewhere
##  using bellow commented out section as a template
#		elif [ -d "" ]; then
#			Func_message "# Func_make_or_copy_easy_rsa_examples running: " '3' '4'
#			cp -R "" "${Var_easyrsa_working_path}"
		else
			## TO-DO : Add options to clone and/or make easy-rsa
			##  from source
			Func_message "# Func_make_or_copy_easy_rsa_examples running: exit 1" '3' '4'
			exit 1
		fi
	else
			Func_message "# Func_make_or_copy_easy_rsa_examples passing control back to: Func_write_easyrsa_vars" '3' '4'
	fi
}
Func_write_easyrsa_vars(){
	Func_message "# Func_write_easyrsa_vars running: Func_make_or_copy_easy_rsa_examples" '2' '3'
	Func_make_or_copy_easy_rsa_examples
	if [ "$?" != "0" ]; then
		Func_message "# Func_write_easyrsa_vars running: exit 1" '2' '3'
		exit 1
	fi
	if [ -d "${Var_easyrsa_working_path}" ]; then
		Func_message "# Func_write_easyrsa_vars writing: ${Var_easyrsa_working_path}/vars" '2' '3'
		cat > "${Var_easyrsa_working_path}/vars" <<EOF
export EASY_RSA="\$(pwd)"
export OPENSSL="openssl"
export PKCS11TOOL="pkcs11-tool"
export GREP="grep"
export KEY_CONFIG=\$(\${EASY_RSA}/whichopensslcnf \${EASY_RSA})
export KEY_DIR="\${EASY_RSA}/keys"
echo "# Note running './clean-all' will preform 'rm -rf' on directory: \${KEY_DIR}"
export PKCS11_MODULE_PATH="dummy"
export PKCS11_PIN="dummy"
export KEY_SIZE="${Var_easyrsa_key_size}"
export CA_EXPIRE="${Var_easyrsa_ca_expire}"
export KEY_EXPIRE="${Var_easyrsa_key_expire}"
export KEY_COUNTRY="${Var_easyrsa_key_country}"
export KEY_PROVINCE="${Var_easyrsa_key_province}"
export KEY_CITY="${Var_easyrsa_key_city}"
export KEY_ORG="${Var_easyrsa_key_org}"
export KEY_EMAIL="${Var_easyrsa_key_email}"
export KEY_OU="${Var_easyrsa_key_ou}"
export KEY_NAME="${Var_easyrsa_key_name}"
EOF
	else
		Func_message "# Func_write_easyrsa_vars cannot write: ${Var_easyrsa_working_path}/vars" '2' '3'
		exit 1
	fi
}
Func_easyrsa_server_copy_certs(){
	_source_cert_path="${1}"
	_destination_cert_path="${2}"
	_destination_cert_dir="${_destination_cert_path%/*}"
	if [ -f "${_source_cert_path}" ]; then
		if ! [ -d "${_destination_cert_dir}" ]; then
			Func_message "# Func_easyrsa_server_copy_certs running: mkdir -p \"${_destination_cert_dir}\"" '3' '4'
			mkdir -p "${_destination_cert_dir}"
		fi
		Func_message "# Func_easyrsa_server_copy_certs running: cp \"${_source_cert_path}\" \"${_destination_cert_path}\"" '3' '4'
		cp "${_source_cert_path}" "${_destination_cert_path}"
	else
		Func_message "# Func_easyrsa_server_copy_certs running: exit 1" '3' '4'
		exit 1
	fi
}
Func_easyrsa_server_gen_certs(){
	if [ -d "${Var_easyrsa_working_path}" ]; then
		_old_pwd="${PWD}"
		Func_message "# Func_easyrsa_server_gen_certs running: cd \"${Var_easyrsa_working_path}\"" '2' '3'
		cd "${Var_easyrsa_working_path}"
		Func_message "# Func_easyrsa_server_gen_certs running: source ./vars" '2' '3'
		source ./vars
		Func_message "# Func_easyrsa_server_gen_certs running: ./clean-all" '2' '3'
		./clean-all
		Func_message "# Func_easyrsa_server_gen_certs running: ./build-dh" '2' '3'
		./build-dh
		Func_message "# Func_easyrsa_server_gen_certs running: ./pkitool --initca" '2' '3'
		./pkitool --initca
		Func_message "# Func_easyrsa_server_gen_certs running: ./pkitool --server ${Var_easyrsa_server_name}" '2' '3'
		./pkitool --server ${Var_easyrsa_server_name}
		Func_message "# Func_easyrsa_server_gen_certs running: cd \"${Var_easyrsa_working_path}/keys\"" '2' '3'
		cd "${Var_easyrsa_working_path}/keys"
		Func_message "# Func_easyrsa_server_gen_certs running: openvpn --genkey --secret ta.key" '2' '3'
		openvpn --genkey --secret ta.key
		Func_message "# Func_easyrsa_server_gen_certs running: Func_easyrsa_server_copy_certs \"${Var_easyrsa_working_path}/keys/ca.crt\" \"${Var_ovpns_ca_path}\"" '2' '3'
		Func_easyrsa_server_copy_certs "${Var_easyrsa_working_path}/keys/ca.crt" "${Var_ovpns_ca_path}"
		Func_message "# Func_easyrsa_server_gen_certs running: Func_easyrsa_server_copy_certs \"${Var_easyrsa_working_path}/keys/${Var_easyrsa_server_name}.crt\" \"${Var_ovpns_cert_path}\"" '2' '3'
		Func_easyrsa_server_copy_certs "${Var_easyrsa_working_path}/keys/${Var_easyrsa_server_name}.crt" "${Var_ovpns_cert_path}"
		Func_message "# Func_easyrsa_server_gen_certs running: Func_easyrsa_server_copy_certs \"${Var_easyrsa_working_path}/keys/${Var_easyrsa_server_name}.key\" \"${Var_ovpns_key_path}\"" '2' '3'
		Func_easyrsa_server_copy_certs "${Var_easyrsa_working_path}/keys/${Var_easyrsa_server_name}.key" "${Var_ovpns_key_path}"
		Func_message "# Func_easyrsa_server_gen_certs running: Func_easyrsa_server_copy_certs \"${Var_easyrsa_working_path}/keys/dh${Var_easyrsa_key_size}.pem\" \"${Var_ovpns_dh_path}\"" '2' '3'
		Func_easyrsa_server_copy_certs "${Var_easyrsa_working_path}/keys/dh${Var_easyrsa_key_size}.pem" "${Var_ovpns_dh_path}"
		Func_message "# Func_easyrsa_server_gen_certs running: Func_easyrsa_server_copy_certs \"${Var_easyrsa_working_path}/keys/ta.key\" \"${Var_ovpns_ta_path}\"" '2' '3'
		Func_easyrsa_server_copy_certs "${Var_easyrsa_working_path}/keys/ta.key" "${Var_ovpns_ta_path}"
		Func_message "# Func_easyrsa_server_gen_certs running: cd \"${_old_pwd}\"" '2' '3'
		cd "${_old_pwd}"
		Func_message "# Func_easyrsa_server_gen_certs running: unset _old_pwd" '2' '3'
		unset _old_pwd
	else
		Func_message "# Func_easyrsa_server_gen_certs cannot find directory: ${Var_easyrsa_working_path}" '2' '3'
		exit 1
	fi
}
Func_mkuser_openvpn_server(){
	Func_message "# Func_mkuser_openvpn_server running: adduser --system --shell /usr/sbin/nologin --no-create-home ${Var_ovpns_user}" '2' '3'
	adduser --system --shell /usr/sbin/nologin --no-create-home ${Var_ovpns_user}
}
Func_easyrsa_clients_gen_certs(){
	_client_name="${1}"
	if [ -d "${Var_easyrsa_working_path}" ]; then
		_old_pwd="${PWD}"
		Func_message "# Func_easyrsa_clients_gen_certs running: cd \"${Var_easyrsa_working_path}\"" '3' '4'
		cd "${Var_easyrsa_working_path}"
				case "${Var_ovpnc_pass_yn}" in
					y|Y|yes|Yes|YES)
						_pass="$(cat /dev/urandom | tr -cd '[:print:]' | head -c"${Var_ovpnc_pass_length}")"
						echo "${_client_name}" >> "${Var_ovpnc_config_dir}/${_client_name}.pass"
						echo "${_pass}" >> "${Var_ovpnc_config_dir}/${_client_name}.pass"
						Func_message "# Func_easyrsa_clients_gen_certs running: tail -n1 \"${Var_ovpnc_config_dir}/${_client_name}.pass\" | ./pkitool --pass ${_client_name}" '3' '4'
						tail -n1 "${Var_ovpnc_config_dir}/${_client_name}.pass" | ./pkitool --pass ${_client_name}
					;;
					*)
						Func_message "# Func_easyrsa_clients_gen_certs running: ./pkitool ${_client_name}" '3' '4'
						./pkitool ${_client_name}
					;;
				esac
		Func_message "# Func_easyrsa_clients_gen_certs running: cd \"${_old_pwd}\"" '3' '4'
		cd "${_old_pwd}"
		Func_message "# Func_easyrsa_clients_gen_certs running: unset _old_pwd" '3' '4'
		unset _old_pwd
	else
		Func_message "# Func_easyrsa_clients_gen_certs cannot find: ${Var_easyrsa_working_path}" '3' '4'
		exit 1
	fi
}
Func_write_openvpn_ipp_config(){
	_client_name="${1}"
	if [ -f "${Var_ovpns_ipp_path}" ]; then
		_last_client_ip="$(tail -n1 "${Var_ovpns_ipp_path}" | awk '{gsub(","," "); print $2}')"
		_client_ip="${_last_client_ip%.*}.$((${_last_client_ip##*.}+4))"
		Func_message "# Func_write_openvpn_ipp_config writing [${_client_name},${_client_ip}] to: ${Var_ovpns_ipp_path}" '3' '4'
		cat >> "${Var_ovpns_ipp_path}" <<EOF
${_client_name},${_client_ip}
EOF
	else
		_client_ip="${Var_ovpns_internal_ip%.*}.4"
		Func_message "# Func_write_openvpn_ipp_config writing [${_client_name},${_client_ip}] to: ${Var_ovpns_ipp_path}" '3' '4'
		cat >> "${Var_ovpns_ipp_path}" <<EOF
${_client_name},${_client_ip}
EOF
	fi
}
Func_write_openvpn_client_config(){
	if [ -d "${Var_easyrsa_working_path}" ]; then
		if ! [ -d "${Var_ovpnc_config_dir}" ]; then
			Func_message "# Func_write_openvpn_client_config running: mkdir -p \"${Var_ovpnc_config_dir}\"" '2' '3'
			mkdir -p "${Var_ovpnc_config_dir}"
		fi
		for _client_name in ${Var_ovpnc_names//,/ }; do
			if ! [ -f "${Var_ovpnc_config_dir}/${_client_name}.ovpn" ]; then
				Func_message "# Func_write_openvpn_client_config running: Func_easyrsa_clients_gen_certs \"${_client_name}\"" '2' '3'
				Func_easyrsa_clients_gen_certs "${_client_name}"
				Func_message "# Func_write_openvpn_client_config running: Func_write_openvpn_ipp_config \"${_client_name}\"" '2' '3'
				Func_write_openvpn_ipp_config "${_client_name}"
				_client_path="${Var_ovpnc_config_dir}/${_client_name}.ovpn"
				Func_message "# Func_write_openvpn_client_config starting config: ${_client_path}" '2' '3'
				cat > "${_client_path}" <<EOF
client
dev ${Var_ovpn_tun_or_tap:-tun}
nobind
nouser
nogroup
persist-key
persist-tun
ca [inline]
cert [inline]
key [inline]
tls-auth [inline] 1
verb ${Var_ovpnc_verbosity}
keepalive 10 120
remote-cert-tls server
proto ${Var_ovpn_protocal}
cipher ${Var_ovpn_cipher}
comp-lzo
tls-cipher ${Var_ovpn_tls_cipher}
block-outside-dns
EOF
				if [ ${#Var_ovpnc_win32_tap} != "0" ]; then
					Func_message "# Func_write_openvpn_client_config appending [dev-node ${Var_ovpnc_win32_tap}] to: ${_client_path}" '2' '3'
					cat >> "${_client_path}" <<EOF
dev-node ${Var_ovpnc_win32_tap}
EOF
				fi
				for _host_port in ${Var_ovpnc_hosts_ports//,/ }; do
					_host="${_host_port%%*:}"
					_port="${_host_port##*:}"
					Func_message "# Func_write_openvpn_client_config appending [remote ${_host} ${_port}] to: ${_client_path}" '2' '3'
					cat >> "${_client_path}" <<EOF
remote ${_host} ${_port}
EOF
				done
				Func_message "# Func_write_openvpn_client_config appending [remote-random] & [resolv-retry infinite] to: ${_client_path}" '2' '3'
				cat >> "${_client_path}" <<EOF
remote-random
resolv-retry infinite
EOF
				if [ "${#Var_ovpnc_http_proxies_ports}" != "0" ]; then
					Func_message "# Func_write_openvpn_client_config appending [http-proxy-retry] to: ${_client_path}" '2' '3'
					cat >> "${_client_path}" <<EOF
http-proxy-retry
EOF
					for _host_port in ${Var_ovpnc_http_proxies_ports//,/ }; do
						_host="${_host_port%%*:}"
						_port="${_host_port##*:}"
						Func_message "# Func_write_openvpn_client_config appending [http-proxy ${_host} ${_port}] to: ${_client_path}" '2' '3'
						cat >> "${_client_path}" <<EOF
http-proxy ${_host} ${_port}
EOF
					done
				fi
				case "${Var_ovpnc_pass_yn}" in
					y|Y|yes|Yes|YES)
						Func_message "# Func_write_openvpn_client_config appending [auth-user-pass \"${_client_name}.pass\"] to: ${_client_path}" '2' '3'
						cat >> "${_client_path}" <<EOF
auth-user-pass "${_client_name}.pass"
EOF
					;;
				esac
				if [ -f "${Var_ovpnc_config_dir}/${_client_name}.crt" ]; then
					Func_message "# Func_write_openvpn_client_config embeding [${Var_ovpnc_config_dir}/${_client_name}.crt] within: ${_client_path}" '2' '3'
					cat >> "${_client_path}" <<EOF
<cert>
EOF
					cat "${Var_ovpnc_config_dir}/${_client_name}.crt" >> "${_client_path}"
					cat >> "${_client_path}" <<EOF
</cert>
EOF
				fi
				if [ -f "${Var_ovpnc_config_dir}/${_client_name}.key" ]; then
					Func_message "# Func_write_openvpn_client_config embeding [${Var_ovpnc_config_dir}/${_client_name}.key] within: ${_client_path}" '2' '3'
					cat >> "${_client_path}" <<EOF
<key>
EOF
					cat "${Var_ovpnc_config_dir}/${_client_name}.key" >> "${_client_path}"
					cat >> "${_client_path}" <<EOF
</key>
EOF
				fi
				if [ -f "${Var_ovpns_config_dir}/ca.crt" ]; then
					Func_message "# Func_write_openvpn_client_config embeding [${Var_ovpns_config_dir}/ca.crt] within: ${_client_path}" '2' '3'
					cat >> "${_client_path}" <<EOF
<ca>
EOF
					cat "${Var_ovpns_config_dir}/ca.crt" >> "${_client_path}"
					cat >> "${_client_path}" <<EOF
</ca>
EOF
				fi
				if [ -f "${Var_ovpns_config_dir}/ta.key" ]; then
					Func_message "# Func_write_openvpn_client_config embeding [${Var_ovpns_config_dir}/ta.key] within: ${_client_path}" '2' '3'
					cat >> "${_client_path}" <<EOF
key-direction 1
<tls-auth>
EOF
					cat "${Var_ovpns_config_dir}/ta.key" >> "${_client_path}"
					cat >> "${_client_path}" <<EOF
</tls-auth>
EOF
				fi
				Func_message "# Func_write_openvpn_client_config NOTICE - files [${_client_path}] & [${_client_name}.pass] (if available) should be transfered to client [${_client_name}] securly to connect to server name [${Var_easyrsa_server_name}]" '2' '3'
##				End of writing config file for client name
			fi
		done
		Func_message "# Func_write_openvpn_client_config NOTICE - $(ls -hal "${Var_ovpnc_config_dir}")" '2' '3'
	else
		Func_message "# Func_write_openvpn_client_config cannot find: ${Var_easyrsa_working_path}" '2' '3'
		exit 1
	fi
}
Func_write_iptables_config(){
	if ! [ -d "${Var_iptables_config_path%/*}" ]; then
		Func_message "# Func_write_iptables_config running: mkdir -p \"${Var_iptables_config_path%/*}\"" '2' '3'
		mkdir -p "${Var_iptables_config_path%/*}"
	fi
	if [ -f "${Var_iptables_config_path}" ]; then
		_date="$(date -u +%s)"
		Func_message "# Func_write_iptables_config running: mv \"${Var_iptables_config_path}\" \"${Var_iptables_config_path}.${_date}\"" '2' '3'
		mv "${Var_iptables_config_path}" "${Var_iptables_config_path}.${_date}"
	fi
	Func_message "# Func_write_iptables_config writing: ${Var_iptables_config_path}" '2' '3'
	cat >> "${Var_iptables_config_path}" <<EOF
#!/usr/bin/env bash
Var_script_name="\${0##*/}"
Var_upOr_down="\${1:-down}"
Var_server_iface="\$(ip addr show | awk '/eth/{gsub(":",""); print \$2}' | head -n1)"
Var_server_IPaddr="\$(ip addr show \${Var_server_iface} | awk '/inet/{print \$2}' | head -n1 | awk '{gsub("\."," "); print \$1"."\$2"."\$3".0/24"}')"
Var_openvpn_conf="\${2:-/etc/openvpn/server.conf}"
Var_bridge_iface="\$(ip addr show | awk '/tun/{gsub(":",""); print \$2}' | head -n1)"
Var_bridge_IPaddr="\$(ip addr show \${Var_bridge_iface} | awk '/inet/{print \$2}' | head -n1 | awk '{gsub("\."," "); print \$1"."\$2"."\$3".0/24"}')"
Var_server_port="\$(grep -vE '#' \${Var_openvpn_conf} | awk '/port/{print \$2}')"
Var_server_protocol="\$(grep -vE '#' \${Var_openvpn_conf} | awk '/proto/{print \$2}')"
Var_allow_clients_on_nat="${Var_ovpns_push_route_yn}"
Var_iptables_input_policy="DROP"
Var_iptables_forward_policy="DROP"
Var_iptables_output_policy="ACCEPT"
#Var_allowed_output_ports="${Var_server_port}"
##########################################################################
##########################################################################
## Writen for the following firejail issues 				##
##	https://github.com/netblue30/firejail/issues/214		##
##	https://github.com/netblue30/firejail/issues/59 		##
## Source of iptables magics 						##
##	https://fedoraproject.org/wiki/Openvpn 				##
##	http://www.ellipsix.net/geninfo/firewall/iptables/index.html	##
##########################################################################
##########################################################################
###	iptables referance (cheat-sheet)
## iptables comment
#-m comment --comment "Comment text upto 256 characters"
## iptables make new custom chain with given name
#-N <chain-name-upto-30-characters>
## Delete chain-name rules
#-F chain-name
## Delete chain-name
#-X chain-name
## iptables append rule to INPUT
#-A INPUT -m comment --comment "some comment" -j DROP
## iptables delete rule on INPUT
#-D INPUT -m comment --comment "some comment" -j DROP
## iptables match protocal; icpm, udp or tcp
# -p ${Var_server_protocol}
Func_check_forward_kernel_policy(){
	case "\$(cat /proc/sys/net/ipv4/ip_forward)" in
		1)
			case "\${Var_upOr_down:-down}" in
				up)
					echo "Forwarding already enabled"
					export Var_redisable_forward="no"
				;;
				*)
					case "\${Var_redisable_forward:-yes}" in
						no)
							echo -e "#\tNotice: not redisabling forwarding"
						;;
						*)
							echo 'echo "0" | tee /proc/sys/net/ipv4/ip_forward'
							echo "0" | tee /proc/sys/net/ipv4/ip_forward
						;;
					esac
				;;
			esac
		;;
		0)
			case "\${Var_upOr_down:-down}" in
				up)
					echo 'echo "1" | tee /proc/sys/net/ipv4/ip_forward'
					echo "1" | tee /proc/sys/net/ipv4/ip_forward
				;;
				*)
					echo -e "#\tNotice: forwarding already disabled"
				;;
			esac
		;;
	esac
}
Func_iptables_forwarding_rules_up_or_down(){
	case "\${Var_upOr_down:-down}" in
		up)
			_A_or_D="A"
		*)
			_A_or_D="D"
		;;
	esac
	iptables -\${_A_or_D} INPUT -s 127.0.0.0/8 -i ! lo -j DROP
	iptables -\${_A_or_D} INPUT -d 127.0.0.0/8 -i ! lo -j DROP
	iptables -\${_A_or_D} OUTPUT -s 127.0.0.0/8 -i ! lo -j DROP
	iptables -\${_A_or_D} OUTPUT -d 127.0.0.0/8 -i ! lo -j DROP
	iptables -\${_A_or_D} INPUT -i lo -j ACCEPT
	iptables -\${_A_or_D} OUTPUT -i lo -j ACCEPT
	iptables -\${_A_or_D} INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	iptables -\${_A_or_D} INPUT -i \${Var_server_iface} -p \${Var_server_protocol:-udp} --dport \${Var_server_port:-1194} -m conntrack --ctstate NEW -j ACCEPT
	iptables -\${_A_or_D} FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	case "\${Var_allow_clients_on_nat:-no}" in
		yes)
			iptables -\${_A_or_D} FORWARD -i \${Var_bridge_iface:-tun0} -o \${Var_server_iface} -s \${Var_bridge_IPaddr} -d \${Var_server_IPaddr} -m conntrack --ctstate NEW -j ACCEPT
		;;
		*)
			iptables -\${_A_or_D} FORWARD -i \${Var_bridge_iface:-tun0} -o \${Var_server_iface} -s \${Var_bridge_IPaddr} -d \${Var_server_IPaddr} -m conntrack --ctstate NEW -j DROP
		;;
	esac
	if [ "\${#Var_allowed_output_ports}" != "0" ]; then
		for _port in \${Var_allowed_output_ports//,/ }; do
			iptables -\${_A_or_D} FORWARD -i \${Var_bridge_iface:-tun0} -o \${Var_server_iface} --dport \${_port} -m conntrack --ctstate NEW -j ACCEPT
		done
	else
		iptables -\${_A_or_D} FORWARD -i \${Var_bridge_iface:-tun0} -o \${Var_server_iface} -s \${Var_bridge_IPaddr} -m conntrack --ctstate NEW -j ACCEPT
	fi
	iptables -t nat -\${_A_or_D} POSTROUTING -o \${Var_server_iface} -s \${Var_bridge_IPaddr} -j MASQUERADE
	if [ "\${#Var_allowed_output_ports}" != "0" ]; then
		iptables -\${_A_or_D} OUTPUT -o \${Var_server_iface} --sport \${Var_server_port} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
		for _port in \${Var_allowed_output_ports//,/ }; do
			iptables -\${_A_or_D} OUTPUT -o \${Var_server_iface} --dport \${_port} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
		done
	else
		iptables -\${_A_or_D} OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
		iptables -\${_A_or_D} OUTPUT -o \${Var_server_iface} -m conntrack --ctstate NEW -j ACCEPT
	fi
}
Func_iptables_policy_rules_up_or_down(){
	case "\${Var_iptables_input_policy:-DROP}" in
		drop|DROP)
			case "\${Var_upOr_down}" in
				up)
					iptables -P INPUT DROP
				;;
				*)
					iptables -P INPUT ACCEPT
				;;
			esac
		;;
		accept|ACCEPT)
			case "\${Var_upOr_down}" in
				up)
					iptables -P INPUT ACCEPT
				;;
				*)
					iptables -P INPUT ACCEPT
				;;
			esac
		;;
		*)
			echo "Did not understand \${Var_iptables_input_policy:-DROP}"
		;;
	esac
	case "\${Var_iptables_forward_policy:-DROP}" in
		drop|DROP)
			case "\${Var_upOr_down}" in
				up)
					iptables -P FORWARD DROP
				;;
				*)
					iptables -P FORWARD ACCEPT
				;;
			esac
		;;
		accept|ACCEPT)
			case "\${Var_upOr_down}" in
				up)
					iptables -P FORWARD ACCEPT
				;;
				*)
					iptables -P FORWARD ACCEPT
				;;
			esac
		;;
		*)
			echo "Did not understand \${Var_default_forward_policy:-DROP}"
		;;
	esac
	case "\${Var_iptables_output_policy:-ACCEPT}" in
		drop|DROP)
			case "\${Var_upOr_down}" in
				up)
					iptables -P OUTPUT DROP
				;;
				*)
					iptables -P OUTPUT ACCEPT
				;;
			esac
		;;
		accept|ACCEPT)
			case "\${Var_upOr_down}" in
				up)
					iptables -P OUTPUT ACCEPT
				;;
				*)
					iptables -P OUTPUT ACCEPT
				;;
			esac
		;;
		*)
			echo "Did not understand \${Var_iptables_output_policy:-ACCEPT}"
		;;
	esac
}
Func_main_iptables_modder(){
	case "\${Var_upOr_down}" in
		up|down)
			Func_check_forward_kernel_policy
			Func_iptables_forwarding_rules_up_or_down
			Func_iptables_policy_rules_up_or_down
		;;
		*)
			echo "# Error, unreconized input."
			echo "# \${Var_script_name} up"
			echo "# \${Var_script_name} down"
			exit 1
		;;
	esac
}
Func_main_iptables_modder
EOF
	## TO-DO : Fix permissions and/or add options for customizing
	##  permissions of the above file and others writen by this script.
#	Func_message "# Func_write_iptables_config running: " '2' '3'
	#Func_message "# Func_write_iptables_config running: " '2' '3'
}
## Do stuff with input and above functions inside bellow function
Func_main(){
	_input=( "$@" )
	if [ "${#_input[@]}" = "0" ]; then
		Func_message "# Func_main running: Func_check_args \"--help\"" '1' '2'
		Func_check_args "--help"
	else
		Func_message "# Func_main running: Func_check_args \"${_input[*]}\"" '1' '2'
		Func_check_args "${_input[@]}"
	fi
	unset -v _input[@]
	## Do stuff with assigned variables
	case "${Var_apt_check_depends_yn}" in
		y|Y|yes|Yes|YES)
			Func_message "# Func_main running: Func_apt_check_install_depends" '1' '2'
			Func_apt_check_install_depends
		;;
		*)
			Func_message "# Func_main skipping: Func_apt_check_install_depends" '1' '2'
		;;
	esac
	case "${Var_ovpns_config_yn}" in
		y|Y|yes|Yes|YES)
			Func_message "# Func_main running: Func_write_easyrsa_vars" '1' '2'
			Func_write_easyrsa_vars
			Func_message "# Func_main running: Func_easyrsa_server_gen_certs" '1' '2'
			Func_easyrsa_server_gen_certs
			Func_message "# Func_main running: Func_mkuser_openvpn_server" '1' '2'
			Func_mkuser_openvpn_server
			Func_message "# Func_main running: Func_write_openvpn_server_config" '1' '2'
			Func_write_openvpn_server_config
		;;
		*)
			Func_message "# Func_main skipping: Func_write_easyrsa_vars, Func_easyrsa_server_gen_certs, Func_mkuser_openvpn_server, Func_write_openvpn_server_config" '1' '2'
		;;
	esac
	case "${Var_ovpnc_config_yn}" in
		y|Y|yes|Yes|YES)
			Func_message "# Func_main running: Func_write_openvpn_client_config" '1' '2'
			Func_write_openvpn_client_config
		;;
		*)
			Func_message "# Func_main skipping: Func_write_openvpn_client_config" '1' '2'
		;;
	esac
	case "${Var_iptables_write_config_yn}" in
		y|Y|yes|Yes|YES)
			Func_message "# Func_main running: Func_write_iptables_config" '1' '2'
			Func_write_iptables_config
		;;
		*)
			Func_message "# Func_main skipping: Func_write_iptables_config" '1' '2'
		;;
	esac
	## TO-DO : Add firejail and/or other "sandboxing" like options
}
Func_message "# ${Var_script_name} running: Func_main \"\$@\"" '0' '1'
Func_main "$@"
Func_message "# ${Var_script_name} finished at: $(date)" '0' '1'
