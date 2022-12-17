Generate a new pair of keys via wg

wg genkey | tee privatekey | wg pubkey > publickey


Upload the newly generate key to Mullvad

curl https://api.mullvad.net/wg/ -d account=YOUR_ACCOUNT_NUMBER --data-urlencode pubkey=`cat publickey`

