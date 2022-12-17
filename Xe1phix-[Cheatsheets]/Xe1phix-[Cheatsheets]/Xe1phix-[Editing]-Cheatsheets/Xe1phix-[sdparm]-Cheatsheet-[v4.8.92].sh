!/bin/sh


sdparm - access SCSI modes pages; read VPD pages; send simple SCSI commandsG



Vital Product Data (VPD) 

	• Part Numbers

	• Serial Numbers

	• Code Sets


sdparm is used to control a SCSI devices behavior

	• spin down SCSI drive

	• Alter Drives Write-back Caching





echo "## ============================================================ ##"
echo "   [+] list the common (generic) mode parameters of a disk:		"
echo "## ============================================================ ##"
sdparm /dev/sda


echo "## ================================================================================ ##"
echo "   [+] list the designators within the device identification VPD page of a disk:		"
echo "## ================================================================================ ##"
sdparm --inquiry /dev/sda





echo "## ====================================================================================== ##"
echo "   [+] If the ejection is being prevented by software then that can be overridden with:	  "
echo "## ====================================================================================== ##"
sdparm --command=unlock /dev/sr0




echo "## ======================================================== ##"
echo -e "\t\t [+] Eject The DVD Drive:								"
echo "## ======================================================== ##"
sdparm --command=eject /dev/sr0




echo "## ============================================================================ ##"
echo "   [+] show all the (known) mode page fields for the Matshita DVD/CD drive.		"
echo "## ============================================================================ ##"
sdparm -a CDROM0

sdparm -a -e




echo "## ======================================================================== ##"
echo "   [+] lists out descriptive information about the pages and fields:			"
echo "## ======================================================================== ##"
sdparm --enumerate --all

sdparm --verbose --enumerate --all



echo "## ======================================================== ##"
echo "   [+] Add extra description section to mode page fields		"
echo "## ======================================================== ##"
sdparm -v -e -l




echo "## ============================================================================================ ##"
echo "   [+] The device identification Vital Product Data (VPD) page (0x83) is decoded and output:		"
echo "## ============================================================================================ ##"
sdparm -i
sdparm --inquiry





--get=

--set=



echo "## ======================================================== ##"
echo "   [+] Sets the given mode page to its default values:		"
echo "## ======================================================== ##"
sdparm -D
sdparm --defaults



echo "## ======================================================== ##"
echo "   [+] Rather than trying to decode VPD pages					"
echo "             Print them out In hex:							"
echo "## ======================================================== ##"
sdparm --hex
sdparm -H




echo "## ======================================================== ##"
echo "   [+] re-establish the manufacturers defaults 				"
echo "       and saved values of the caching mode page:				"
echo "## ======================================================== ##"
sdparm --page=ca --defaults --save /dev/sda



echo "## ============================================================= ##"
echo "   [+] list an ATAPI cd/dvd drives common (mode) parameters:		 "
echo "## ============================================================= ##"
sdparm /dev/sr0






echo "## ======================================================================== ##"
echo "   [+] set the "Writeback Cache Enable" bit In the current values page:
echo "## ======================================================================== ##"
sdparm --set=WCE /dev/sda



set the "Writeback Cache Enable" bit In the current and saved values page:

sdparm --set=WCE --save /dev/sda



set the "Writeback Cache Enable" and clear "Read Cache Disable":

sdparm --set=WCE --clear=RCD --save /dev/sda



