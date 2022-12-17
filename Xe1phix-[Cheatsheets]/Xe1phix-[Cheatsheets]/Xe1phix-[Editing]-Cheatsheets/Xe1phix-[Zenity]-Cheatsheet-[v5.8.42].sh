#!/bin/sh
## Zenity.sh





zenity   --title  "Select  Host" --entry --text "Select the host you would like to flood-ping"

echo "\t\tDisplay a File Selector Dialog, Then  Remove That  File"
zenity  --title="Select A File To Remove" --file-selection


zenity  --question --title "Alert"   --text  "Microsoft  Windows has been found! Would you like to remove it?"

echo -e "\t\t\tFinding All Header Files...."
 find . -name '*.h' |  zenity  --list  --title  "Search  Results" --text "Finding all header files.." --column "Files"

echo -e "\t\tShow A Notification In The Message Tray"
zenity  --notification  --window-icon=update.png  --text "System update necessary!"

echo -e "\t\tCreate a Check List Dialog
zenity  --list  --checklist  --column "Harden" --column "Item" TRUE Apples TRUE Oranges FALSE Pears FALSE Toothpaste

echo -e "\t\tDisplay a progress dialog while searching for all"
echo -e "\t\tThe postscript  files in your home directory"
find $HOME -name '*.ps' | zenity --progress --pulsate


echo -e "\t\t#####################################"
echo -e "\t\t########## Zenity-File-Selection.sh ############"
echo -e "\t\t#####################################"

#!/bin/sh

FILE=`zenity --file-selection --title="Select a File"`

case $? in
         0)
                echo "\"$FILE\" selected.";;
         1)
                echo "No file selected.";;
        -1)
                echo "An unexpected error has occurred.";;
esac

########################################
########################################





echo -e "\t\t################################"
echo -e "\t\t########## Zenity-Forms.sh ############"
echo -e "\t\t################################"

#!/bin/sh

zenity --forms --title="Add Friend" \
     --text="Enter information about your friend." \
     --separator="," \
     --add-entry="First Name" \
     --add-entry="Family Name" \
     --add-entry="Email" \
     --add-calendar="Birthday" >> addr.csv

case $? in
    0)
        echo "Friend added.";;
    1)
        echo "No friend added."
     ;;
    -1)
        echo "An unexpected error has occurred."
     ;;
esac

########################################
########################################




echo -e "\t\t################################"
echo -e "\t\t##### Zenity-Text-Information-Dialog.sh ######"
echo -e "\t\t################################"

#!/bin/sh

# You must place file "COPYING" in same folder of this script.
FILE=`dirname $0`/COPYING

zenity --text-info \
       --title="License" \
       --filename=$FILE \
       --checkbox="I read and accept the terms."

case $? in
    0)
        echo "Start installation!"
     # next step
     ;;
    1)
        echo "Stop installation!"
     ;;
    -1)
        echo "An unexpected error has occurred."
     ;;
esac

########################################
########################################





echo -e "\t\t################################"
echo -e "\t\t##### Create-A-Progress-Dialog.sh #########"
echo -e "\t\t################################"



#!/bin/sh
(
echo "10" ; sleep 1
echo "# Updating mail logs" ; sleep 1
echo "20" ; sleep 1
echo "# Resetting cron jobs" ; sleep 1
echo "50" ; sleep 1
echo "This line will just be ignored" ; sleep 1
echo "75" ; sleep 1
echo "# Rebooting system" ; sleep 1
echo "100" ; sleep 1
) |
zenity --progress \
  --title="Update System Logs" \
  --text="Scanning mail logs..." \
  --percentage=0

if [ "$?" = -1 ] ; then
        zenity --error \
          --text="Update canceled."
fi






########################################
########################################

