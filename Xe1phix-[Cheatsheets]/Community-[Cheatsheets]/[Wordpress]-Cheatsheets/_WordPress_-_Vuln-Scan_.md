# Bash script to scan PHP files for potential vulnerabilities
# 
# Currently being copy-pasted to bootstrap code audits for WordPress plugins
#
# Based off of @dustyfresh's https://github.com/dustyfresh/PHP-vulnerability-audit-cheatsheet
#


# XSS
clear && \
 { figlet "XSS" && \
	 echo "" && \
	 date +'%Y-%m-%d at %H:%m:%S' && \
	 echo "" && \
	 grep -Ri --include="*.php" "\$_" . | grep "echo" && \
	 grep -Ri --include="*.php" "\$_GET" . | grep "echo" && \
	 grep -Ri --include="*.php" "\$_POST" . | grep "echo" && \
	 grep -Ri --include="*.php" "\$_COOKIE" . | grep "echo" && \
	 grep -Ri --include="*.php" "\$_REQUEST" . | grep "echo"; } >scan-xss.txt 2>&1


# Command Execution
clear && \
	{ figlet "Command Execution" && \
		echo "" && \
		date +'%Y-%m-%d at %H:%m:%S' && \
		echo "" && \
		grep -Ri --include="*.php" "shell_exec(" . && \
		grep -Ri --include="*.php" "system(" . && \
		grep -Ri --include="*.php" "exec(" . && \
		grep -Ri --include="*.php" "popen(" . && \
		grep -Ri --include="*.php" "passthru(" . && \
		grep -Ri --include="*.php" "proc_open(" . && \
		grep -Ri --include="*.php" "pcntl_exec(" .; } >scan-command_exec.txt 2>&1


# Code Execution
#   - This is forkbombing
clear && \
	{ figlet "Code Execution" && \
		echo "" && \
		date +'%Y-%m-%d at %H:%m:%S' && \
		echo "" && \
		grep -Ri --include="*.php" "eval(" . && \
		grep -Ri --include="*.php" "assert(" . && \
		grep -Ri --include="*.php" "preg_replace" . | grep "/e" && \
		grep -Ri --include="*.php" "create_function(" .; } >scan-code_exec.txt 2>&1


# SQLi
clear && \
	{ figlet "SQLi" && \
		echo "" && \
		date +'%Y-%m-%d at %H:%m:%S' && \
		echo "" && \
		grep -Ri --include="*.php" "\$sql" . && \
		grep -Ri --include="*.php" "\$qry" . && \
		grep -Ri --include="*.php" "\$query" . && \
		echo "" && \
		echo "Prime targets:" && \
		echo "" && \
		grep -Ri --include="*.php" "\$sql" . | grep "\$_"; } >scan-sqli.txt 2>&1


# PHP Object injection
clear && \
	{ figlet "PHP Object Inject" && \
		echo "" && \
		date +'%Y-%m-%d at %H:%m:%S' && \
		echo "" && \
		grep -Ri --include="*.php" "unserialize(" .; } >scan-php_inject.txt 2>&1


# Debug
clear && \
	{ figlet "Debugging" && \
		echo "" && \
		date +'%Y-%m-%d at %H:%m:%S' && \
		echo "" && \
		grep -Ri --include="*.php" "debug" . && \
		grep -Ri --include="*.php" "\$_GET['dev']" . && \
		grep -Ri --include="*.php" "\$_GET['debug']" . && \
		grep -Ri --include="*.php" "\$_GET['test']" .; } >scan-debug.txt 2>&1


# Misc
clear && \
	{ figlet "Misc." && \
		echo "" && \
		date +'%Y-%m-%d at %H:%m:%S' && \
		echo "" && \
		echo "Path Traversal:" && \
		grep -Ri --include="*.php" "file_get_contents" . && \
		echo "" && \
		echo "RFI/LFI:" && \
		grep -Ri --include="*.php" "file_include" . | grep "\$_" && \
		grep -Ri --include="*.php" "include" . | grep "\$_" && \
		grep -Ri --include="*.php" "include_once" . | grep "\$_" && \
		grep -Ri --include="*.php" "require" . | grep "\$_" && \
		grep -Ri --include="*.php" "require_once" . | grep "\$_" && \
		echo "" && \
		echo "Redirect:" && \
		grep -Ri --include="*.php" "header" . | grep "\$_" && \
		echo "" && \
		echo "User Agent:" && \
		grep -Ri --include="*.php" "$_SERVER[\"HTTP_USER_AGENT\"]" . && \
		echo "" && \
		echo "Information Leak:" && \
		grep -Ri --include="*.php" "phpinfo" .; } >scan-misc.txt 2>&1