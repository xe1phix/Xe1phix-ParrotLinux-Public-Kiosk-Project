#!/bin/sh
## #######
## ## Xe1phix-SourceAddressVerification-v1.5.sh
## #######
## 




#!/bin/sh
## =========================================================== ##
## 	[+] Xe1phix-SourceAddressVerification-BootTime-v1.5.sh
## =========================================================== ##
## 		Executes Eefore any Network Devices are Enabled:
## =========================================================== ##
echo -n "Enabling source address verification..."
echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter
echo "done"



#!/bin/sh
## =========================================================== ##
## 	[+] Xe1phix-SourceAddressVerification-Runtime-v1.5.sh
## =========================================================== ##
## 			  After Network Devices Are Enabled:
## =========================================================== ##
CONF_DIR=/proc/sys/net/ipv4/conf
CONF_FILE=rp_filter
if [ -e ${CONF_DIR}/all/${CONF_FILE} ]; then
		echo -n "Setting up IP spoofing protection..."
		for f in ${CONF_DIR}/*/${CONF_FILE}; do
				echo 1 > $f
		done
		echo "done"
fi

