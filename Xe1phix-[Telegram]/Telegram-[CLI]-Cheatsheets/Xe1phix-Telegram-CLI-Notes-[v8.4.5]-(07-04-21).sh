#!/bin/sh

TG_HOME /home/$TG_USER
mkdir "$TG_HOME"

TG_PUBKEY "$TG_HOME"/tg/tg-server.pub


# set user/group IDs
RUN groupadd -r "$TG_USER" --gid=999 && useradd -r -g "$TG_USER" --uid=999 "$TG_USER"



--verbosity -u $User -k $PubKey 

--phone 5153059213 --rsa-key $PubKey --tcp-port 443 --udp-socket TelegramSocket

--phone 5153059213 --rsa-key /etc/telegram-cli/server.pub --tcp-port 443 --udp-socket TelegramSocket --disable-link-preview --sync-from-start

-L <log-name>       log file name
--logname $File
--log-level 


--username
-U <user-name>      change uid after start
-G <group-name>     change gid after start
--config $Config 

--tcp-port 
-P <port>           port to listen for input commands

-E                  diable auto accept of encrypted chats
--disable-auto-accept



--disable-link-preview

--permanent-msg-ids                  use permanent msg ids
  --permanent-peer-ids                 use permanent peer ids







#cat /var/log/telegram.lua.log |egrep '<k>|<sh>|<sg>|<sr>|<sa>'|awk -F ';' '{print $2}'|sort|uniq -c|sort
cat /var/log/telegram.lua.log |egrep '<k>|<sh>|<sg>|<sr>|<sa>'|sed 's/<//g'|sed 's/>//g'|awk -F ';' '{print $2}'|sort|uniq -c|awk -F ' ' {'print $2"-"$3":"$1""'}|awk -F '_' '{print $2}'|sort -k2 -n -t':' -r|tr '\n' ' - '




telegram-cli -k /home/pi/tg/tg-server.pub -W -e \"add_contact $1 $2 $3\"

telegram-cli -k /home/pi/tg/tg-server.pub -W -e "msg $1 $2"
echo "msg $1 "$2"" | nc localhost 54621

echo "send_photo "$1 $2"" | nc localhost 54621




telegram-cli -k /home/pi/tg/tg-server.pub -W -e "msg $1 $2"
# 1 = empf
# 2 = latitude
# 3 = longitutde
echo "send_location $1 $2 $3" | nc localhost 54621



state="$1"
if [[ $state = "defence" ]]
        then
        (sleep 1; echo "contact_list"; sleep 1; echo "msg user#265204902 '🛡 Защита'") | bin/telegram-cli -W -v -k tg-server.pub
	sleep 120;
        (sleep 1; echo "contact_list"; sleep 1; echo "msg user#265204902 '🇻🇦'") | bin/telegram-cli -W -v -k tg-server.pub
fi
if [[ $state = "caravan" ]]
	then (sleep 1; echo "contact_list"; sleep 1; echo "msg user#265204902 '🐫ГРАБИТЬ КОРОВАНЫ'") | bin/telegram-cli -W -v -k tg-server.pub
fi
if [[ $state = "forest" ]]
	then (sleep 1; echo "contact_list"; sleep 1; echo "msg user#265204902 '🌲Лес'") | bin/telegram-cli -W -v -k tg-server.pub
fi
if [[ $state = "cave" ]]
	then (sleep 1; echo "contact_list"; sleep 1; echo "msg user#265204902 '🕸Пещера'") | bin/telegram-cli -W -v -k tg-server.pub
fi
if [[ $state = "arena" ]]
	then (sleep 1; echo "contact_list"; sleep 1; echo "msg user#265204902 '🔎Поиск соперника'") | bin/telegram-cli -W -v -k tg-server.pub
fi
if [[ $state = "go" ]]
        then bin/telegram-cli -W -v -k tg-server.pub -s scripts/go.lua
fi
if [[ $state = "go-att" ]]
        then bin/telegram-cli -W -v -k tg-server.pub -s scripts/go+att.lua
fi
if [[ $state = "go-helper" ]]
        then (sleep 1; echo "contact_list"; sleep 1; echo "msg user#265204902 '/go'") | bin/telegram-cli -W -v -k tg-server.pub




TELEGRAM_BOT_TOKEN      
Bot token, get it by steps:
On telegram, call 

URL="https://api.telegram.org/bot"
FILE_URL="https://api.telegram.org/file/bot"
URL="https://api.telegram.org/bot${KEY}/sendMessage"
TG_API_URL="https://api.telegram.org/bot$(cat ../telegram-api-key.txt)/sendMessage"





echo ------------------------------------------------------------------------------------------------
echo To get monitoring alerts, person should /start your monitoring bot in telegram.
echo Then you enable alerts for person by adding telegram chat_id from list below to recipients file.
echo You specify recipients file in parameter MSMS_RECIPIENTS of .ini file for your service.
echo ------------------------------------------------------------------------------------------------
curl -s https://api.telegram.org/bot$(cat telegram-api-key.txt)/getUpdates



#################################################################
# send message to telegram
# parameter: message text
# recipients chat id list should be in "recipients.txt" file
#################################################################
function send_message {
    for chat_id  in $(cat $MSMS_RECIPIENTS); do
	curl -s -X POST --connect-timeout 10 $TG_API_URL -d chat_id=$chat_id -d parse_mode="Markdown" -d text="$1"  # > /dev/null
	echo
    done
}






curl -s -X POST -H "Content-Type: application/json" --connect-timeout 3 -m 7 -d @request.json



curl -s -d "chat_id=$CHAT_ID&disable_web_page_preview=1&text=$1" $URL





Telegram-Notifier-unit-status-telegram

#!/bin/bash

UNIT=$1

UNITSTATUS=$(systemctl status $UNIT)
ALERT=$(echo -e "\u26A0")

telegram "$ALERT Unit failed $UNIT $ALERT
Status:
$UNITSTATUS"


unit-status-telegram@.service


[Unit]
Description=Unit Status Telegram Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/unit-status-telegram %I



STATUS=$(ip route show match 0/0)

if [ ! -z "$STATUS" ]; then

    read GATEWAYIP IFACE LOCALIP <<< $(echo $STATUS | awk '{print $3" "$5" "$7}')
    GATEWAYMAC=$(ip neigh | grep "$GATEWAYIP " | awk '{print $5}')

    echo "INTERFACE:   $IFACE"
    echo "GATEWAY IP:  $GATEWAYIP"
    echo "GATEWAY MAC: $GATEWAYMAC"
    echo "LOCAL IP:    $LOCALIP"

    if [ -z $(curl -fsS http://google.com > /dev/null) ]; then
        PUBLICIP=$(dig +short myip.opendns.com @resolver1.opendns.com)

        echo "PUBLIC IP:   $PUBLICIP"
fi




CLIENT_IP=$(echo $SSH_CLIENT | awk '{print $1}')


SRV_HOSTNAME=$(hostname -f)
	SRV_IP=$(hostname -I | awk '{print $1}')

	IPINFO="https://ipinfo.io/${CLIENT_IP}"

	TEXT="Connection from *${CLIENT_IP}* as ${USER} on *${SRV_HOSTNAME}* (*${SRV_IP}*)
	Date: ${DATE}
	More informations: [${IPINFO}](${IPINFO})"

	curl -s -d "chat_id=$i&text=${TEXT}&disable_web_page_preview=true&parse_mode=markdown" $URL > /dev/null
fi
done




@BotFather

/newbot
/mybots



curl $CURL_OPTIONS $URL$TOKEN/getUpdates
curl $CURL_OPTIONS $URL$TOKEN/getUpdates?allowed_updates=message






--bot-token=
--chat-id=
--message=
--file=
--file-id=
--file-type=        
--thumb=        
--thumb-id=     
--parse-mode=
--send-method=
--method=       
--curl-form=    
curl --form-string 
curl --form-string "disable_notification=true"
curl --form-string "disable_web_page_preview=true"
-o "disable_notification=true"
-o "disable_web_page_preview=true"

--curl-args=    
--execute=       
--verbose
--chat-id=


location: -o latitude= -o longitude=
venue: -o latitude= -o longitude= -o title= -o address=
contact: -o phone_number= -o first_name=
poll: -o question= -o options=
dice: [-o emoji=]
chat_action: -o action=
invoice: -o title= -o description= -o payload= -o provider_token= -o  start_parameter= -o currency= -o prices= (provider_token is from @BotFather -> /mybots -> payments -> ...)




On telegram, send a message to the bot.
-X list_chat_ids
 to get bot recently chat ids.




USERNAME=pi
GROUPNAME=pi
LOGFILE=/home/pi/telegramd.log
DAEMON=/usr/bin/telegram-cli
TGPORT=1234
TelegramKeyFile="/etc/telegram-cli/server.pub"

DAEMON_ARGS="-W -b -U $USERNAME -G $GROUPNAME -k $TelegramKeyFile -L $LOGFILE -P $TGPORT -s $ReceiveLua -d -vvvRC"
DAEMON_ARGS="-W -U telegramd -G telegramd -k $TelegramKeyFile -L /var/log/telegramd.log -P $TGPORT -d -vvvRC"



