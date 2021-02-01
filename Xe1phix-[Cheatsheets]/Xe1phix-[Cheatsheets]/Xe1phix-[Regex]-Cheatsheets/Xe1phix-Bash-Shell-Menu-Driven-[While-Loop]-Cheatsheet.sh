#!/bin/sh
##-=========================================================-##
##    [+] Xe1phix-Bash-Shell-Menu-Driven-[While-Loop]-Cheatsheet.sh
##-=========================================================-##
## 
##-=========================================-##
##    [+] A Menu Driven Program Using While Loop:
##-=========================================-##
## --------------------------------------------------------------------------------------------------------------- ##
##     [?] Continues till user selects to exit by pressing 4 option. 
##     [?] The case statement is used to match values against $choice variable
## --------------------------------------------------------------------------------------------------------------- ##
echo "##-========================-##"
echo "##     [+] Set An Infinite Loop:"
echo "##-========================-##"
echo
while :
do
	clear
## ---------------------------------- ##
##     [?] Display Menu
## ---------------------------------- ##
	echo "-------------------------------"
	echo "     M A I N - M E N U"
	echo "-------------------------------"
	echo "1. $Option1"
	echo "2. $Option2"
	echo "3. $Option3"
	echo "4. $ExitOption"

	read -p "Enter your choice [ 1 -4 ] " choice

case $choice in
		1)
			$Option1Choice
			read -p "Press [Enter] key to continue..." readEnterKey
			;;
		2) 
			$Option2Choice
			read -p "Press [Enter] key to continue..." readEnterKey
			;;
		3)
			$Option3Choice
			read -p "Press [Enter] key to continue..." readEnterKey
			;;
		4)
			echo "Exiting... Bye!"
			exit 0
			;;
		*)
			echo "Error: Invalid option..."	
			read -p "Press [Enter] key to continue..." readEnterKey
			;;
	esac		
				
done
