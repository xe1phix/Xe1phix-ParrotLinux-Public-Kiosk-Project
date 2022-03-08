#!/bin/bash
#Basic OATH wrapper using the oathtool
#Simon Moffatt June 2013

#Checks number of arguments being passed is 2
OATHTOOL_LOC=$(which oathtool)

if [ "OATHTOOL_LOC" = "" ]; then

	echo ""
	echo "oathtool not found!  Sudo apt-get install oathtool etc..."
	echo ""
	exit

fi

function menu() {

	clear
	echo "Key and OTP generator and wrapper for oathtool utility"
	echo "------------------------------------------------------"
	echo ""
	echo "1: Generate Secret Key / Token"
	echo "2: Generate HOTP"
	echo "3: Exit"
	echo ""
	echo "------------------------------------------------------"
	echo "Select an option:"
	read option

	#iterate options
	case $option in

		1)
			check_secret		
			;;	
		2)
			generate_HOTP
			;;
		3)
			clear	
			echo "Byeeeeeeeeeeeeeeeeeee :)"
			echo ""			
			exit
			;;
		*)
			menu
			;;
	esac
	
}

function check_secret() {

	clear
	echo "Generating new shared secret..."

	#check to see if shared secret file exists
	if [ -f ".key" ] ; then

		function already_exists() {

				clear
				echo ".key file already exists!"
				echo ""		
				echo "Delete and create a new one? [y or n]"
				read key_create_answer
				case $key_create_answer in
		
					[yY] | [yY][Ee][Ss])
				
						generate_secret	
						;;				
	
					[nN] | [n|N][O|o] )
					
						menu
						;;

					*)
						already_exists

				esac

		}

		already_exists

	#file doesn't exist so create one..
	else
		
		generate_secret
	fi

}

#creates a PoC strength shared secret
function generate_secret() {

	rm -f .key .counter
	echo ""
	echo "Note this secret is purely for testing and is not designed to follow RFC4226 http://www.ietf.org/rfc/rfc4226.txt "
	echo ""
	echo "Enter a random seed:"
	read $seed
	date=$(date +%s)
	host=$(hostname)
	SECRET=$(echo "$date$hostname$seed" | sha256sum | head -c 32)
	echo $SECRET > .key
	chmod 400 .key
	#create counter file for HOTP
	echo 0 > .counter	
	chmod 400 .counter	
	echo ""
	echo "New key: $SECRET"
	echo ""	
	echo "Stored in hidden file in current directory as .key ready to be read by OTP generator"
	echo ""	
	read -p "Press [Enter] key to return to menu"
	menu

}



function read_secret() {

	#if .secret exists read it in along with current counter
	if [ -f ".key" ] && [ -f ".counter" ] ; then
	
		KEY=$(cat .key)
		COUNTER=$(cat .counter)

	#push back to menu to create new key
	else
		echo ""
		echo ".key shared secret file not found! Select Generate Secret to create one"
		echo ""	
		read -p "Press [Enter] key to return to menu"
		menu

	fi

}

function generate_HOTP() {
	
	clear
	echo "Generating HOTP..."
	#read secret key in
	read_secret

	#generate next OTP using key	
	echo ""
	echo $(oathtool -v -c $COUNTER $KEY)
	echo ""

	#increment counter for next time
	COUNTER=$(($COUNTER + 1))
	rm -f .counter	
	echo $COUNTER > .counter
	chmod 400 .counter
	
	#back to menu
	read -p "Press [Enter] key return to menu"
	menu
}


#Initiate menu
menu


