#!/bin/sh
## 
##-=======================================-##
##   [+] VerifyFDroidRepository-v4.7.sh
##-=======================================-##
## 
## --------------------------------------------------------------------------------- ##
##   gpg --full-gen-key --enable-large-rsa
## --------------------------------------------------------------------------------- ##
## 
## ------------------------------------------------------------------------------------------------------------------------------------------ ##
##   gpg --verbose --keyid-format 0xlong --keyserver hkp://pool.sks-keyservers.net --recv-keys 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
##   gpg --fingerprint --with-subkey-fingerprint 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
##   gpg --edit-key 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
##   gpg --keyid-format 0xlong --verbose --lsign 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
## ------------------------------------------------------------------------------------------------------------------------------------------ ##
## 
## 
## ------------------------------------------------------------------------------------------------------------------------------------------ ##
## gpg --verbose --keyid-format 0xlong --keyserver hkp://pool.sks-keyservers.net --recv-keys 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
## gpg --verbose --keyid-format 0xlong --import FDroid.asc
## gpg --verbose --keyid-format 0xlong --import f-droid.org-signing-key.gpg
## gpg --verbose --keyid-format 0xlong --import public.asc
## ------------------------------------------------------------------------------------------------------------------------------------------ ##
## gpg --fingerprint --with-subkey-fingerprint 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
## ------------------------------------------------------------------------------------------------------------------------------------------ ##
## gpg --edit-key 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
## gpg --keyid-format 0xlong --verbose --lsign 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
## ------------------------------------------------------------------------------------------------------------------------------------------ ##
## 
## 
echo "[+]==========================================================================================[+]"
echo "     [+] FDroidMainRepo="https://f-droid.org/repo"                                              "
echo "[+]==========================================================================================[+]"
echo "     [+] GuardianProjectMainRepo="https://guardianproject.info/fdroid/repo"                     "
echo "     [+] export GuardianProjectMainRepo="https://guardianproject.info/fdroid/repo"              "
echo "[+]==========================================================================================[+]"
echo "     [+] GuardianProjectAWS="https://s3.amazonaws.com/guardianproject/fdroid/repo"              "
echo "     [+] export GuardianProjectAWS="https://s3.amazonaws.com/guardianproject/fdroid/repo"       "
echo "[+]==========================================================================================[+]"
echo "     [+] TorHiddenServiceFDroidRepo="http://bdf2wcxujkg6qqff.onion/fdroid/repo"                 "
echo "     [+] export TorHiddenServiceFDroidRepo="http://bdf2wcxujkg6qqff.onion/fdroid/repo"            "
echo "[+]==========================================================================================[+]"
echo "     [+] FDroidIOFrontend="https://f-droid.i2p.io/repo/"                                                  "
echo "     [+] export FDroidIOFrontend="https://f-droid.i2p.io/repo/"                                           "   
echo "[+]==========================================================================================[+]"
echo "     [+] F-DroidArchive="https://f-droid.org/archive"                                         "
echo "     [+] export F-DroidArchive="https://f-droid.org/archive"                                  "
echo "[+]==========================================================================================[+]"
echo "     [+] FDroidClientGitRepo="https://gitlab.com/fdroid/fdroidclient"                           "
echo "     [+] export FDroidClientGitRepo="https://gitlab.com/fdroid/fdroidclient"                    "
echo "[+]==========================================================================================[+]"
echo "##   [+] GPG signing key: "F-Droid <admin@f-droid.org>"                                         "
echo "[+]==========================================================================================[+]"
echo 
echo "## ------------------------------------------------------------------------------- ##"
echo "     [+] FDroidGPGFpr="37D2 C987 89D8 3119 4839 4E3E 41E7 044E 1DBA 2E89"            "
echo "     [+] FDroidGPGSubkeyFpr="802A 9799 0161 1234 6E1F EFF4 7A02 9E54 DD5D CE7A"      "
echo "## ------------------------------------------------------------------------------- ##"
echo 
echo "[+]=============================================================================================================[+]   "
echo "     [+] git tags signed by Daniel Martí <mvdan@mvdan.cc> aka Daniel Martí <mvdan@fsfe.org> with fingerprint:         "
echo "[+]=============================================================================================================[+]   "
echo "     [+] FDroidGitFpr="A9DA 13CD F7A1 4ACD D3DE E530 F4CA FFDB 4348 041C"                                             "
echo "[+]=============================================================================================================[+]   "
echo "##   [+] FDroidAPKSigningKey=                                                                                         "
echo "##                                                                                                                    "
echo "##   [+] Certificate fingerprints:                                                                                    "
echo "##       MD5:  17:C5:5C:62:80:56:E1:93:E9:56:44:E9:89:79:27:86                                                        "
echo "##       SHA1: 05:F2:E6:59:28:08:89:81:B3:17:FC:9A:6D:BF:E0:4B:0F:A1:3B:4E                                            "
echo "##       SHA256: 43:23:8D:51:2C:1E:5E:B2:D6:56:9F:4A:3A:FB:F5:52:34:18:B8:2E:0A:3E:D1:55:27:70:AB:B9:A9:C9:CC:AB      "
echo "[+]================================================================================================================[+]"
echo
echo "[+]===================================================================================[+]"
echo "                  [+] GPG signing key: F-Droid <admin@f-droid.org>                       "
echo "[+]===================================================================================[+]"
echo "## ----------------------------------------------------------------------------------- ##"
echo "##   [+] Primary key fingerprint: 37D2 C987 89D8 3119 4839 4E3E 41E7 044E 1DBA 2E89      "
echo "##   [+] Subkey fingerprint: 802A 9799 0161 1234 6E1F EFF4 7A02 9E54 DD5D CE7A           "
echo "## ----------------------------------------------------------------------------------- ##"
## 
## ----------------------------------------------- ##
##   cp -v VerifyFDroidRepo.sh ~/Downloads/FDroid
##   cd ~/Downloads/FDroid/
##   chmod +x VerifyFDroidRepo.sh
##   ./VerifyFDroidRepo.sh 
## ----------------------------------------------- ##
## 
## ----------------------------- ##
##   gpg --verify-files
##   gpg --multifile --verify 
##   gpg --multifile --encrypt 
##   gpg --multifile --decrypt 
## ----------------------------- ##
## 
##-==================================================================================================-##
gpg --keyid-format 0xlong --verbose --verify app.librenews.io.librenews_5.apk.asc
gpg --keyid-format 0xlong --verbose --verify at.tomtasche.reader_24.apk.asc
gpg --keyid-format 0xlong --verbose --verify be.uhasselt.privacypolice_13.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.adguard.android.contentblocker_21002201.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.artifex.mupdf.viewer.app_30.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.catchingnow.tinyclipboardmanager_57.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.commit451.gitlab_2060300.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.davidshewitt.admincontrol_5.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.fsck.k9_26000.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.ghostsq.commander_364.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.gianlu.dnshero_15.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.github.axet.hourlyreminder_373.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.github.onetimepass_1002002.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.github.yeriomin.yalpstore_45.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.majeur.applicationsinfo_7.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.mantz_it.rfanalyzer_1303.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.mrbimc.selinux_20171031.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.notecryptpro_19.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.nutomic.ensichat_17.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.orpheusdroid.screenrecorder_28.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.pavelsikun.runinbackgroundpermissionsetter_8.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.sovworks.edslite_224.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.wireguard.android_437.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.wireguard.android_438.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.wireguard.android_439.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.xabber.androiddev_348.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.yubico.yubiclip_10300.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.yubico.yubiclip_5.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.yubico.yubioath_20001.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.yubico.yubioath_29.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.yubico.yubioath_34.apk.asc
gpg --keyid-format 0xlong --verbose --verify cx.ring_129.apk.asc
gpg --keyid-format 0xlong --verbose --verify de.baumann.browser_83.apk.asc
gpg --keyid-format 0xlong --verbose --verify de.blinkt.openvpn_159.apk.asc
gpg --keyid-format 0xlong --verbose --verify de.k3b.android.intentintercept_301.apk.asc
gpg --keyid-format 0xlong --verbose --verify de.meonwax.soundboard_4.apk.asc
gpg --keyid-format 0xlong --verbose --verify de.srlabs.snoopsnitch_35.apk.asc
gpg --keyid-format 0xlong --verbose --verify dev.ukanth.ufirewall_16400.apk.asc
gpg --keyid-format 0xlong --verbose --verify dev.ukanth.ufirewall_16600.apk.asc
gpg --keyid-format 0xlong --verbose --verify dk.meznik.jan.encrypttext_1.apk.asc
gpg --keyid-format 0xlong --verbose --verify eu.faircode.netguard_2018102001.apk.asc
gpg --keyid-format 0xlong --verbose --verify eu.siacs.conversations_297.apk.asc
gpg --keyid-format 0xlong --verbose --verify FDroid.apk.asc
gpg --keyid-format 0xlong --verbose --verify free.rm.skytube.oss_16.apk.asc
gpg --keyid-format 0xlong --verbose --verify fr.keuse.rightsalert_3.apk.asc
gpg --keyid-format 0xlong --verbose --verify fr.simon.marquis.preferencesmanager_183.apk.asc
gpg --keyid-format 0xlong --verbose --verify fr.simon.marquis.secretcodes_201.apk.asc
gpg --keyid-format 0xlong --verbose --verify im.vector.alpha_81800.apk.asc
gpg --keyid-format 0xlong --verbose --verify in.arjsna.permissionchecker_5.apk.asc
gpg --keyid-format 0xlong --verbose --verify info.guardianproject.ripple_83.apk.asc
gpg --keyid-format 0xlong --verbose --verify jackpal.androidterm_72.apk.asc
gpg --keyid-format 0xlong --verbose --verify kvj.taskw_3.apk.asc
gpg --keyid-format 0xlong --verbose --verify marto.rtl_tcp_andro_20.apk.asc
gpg --keyid-format 0xlong --verbose --verify net.bierbaumer.otp_authenticator_1.apk.asc
gpg --keyid-format 0xlong --verbose --verify net.bierbaumer.otp_authenticator_2.apk.asc
gpg --keyid-format 0xlong --verbose --verify net.bierbaumer.otp_authenticator_3.apk.asc
gpg --keyid-format 0xlong --verbose --verify net.kourlas.voipms_sms_119.apk.asc
gpg --keyid-format 0xlong --verbose --verify net.typeblog.shelter_9.apk.asc
gpg --keyid-format 0xlong --verbose --verify nl.yoerinijs.notebuddy_15.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.adaway_61.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.billthefarmer.editor_124.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.blokada.alarm_306101900.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.bottiger.podcast_424.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.cipherdyne.fwknop2_32.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.connectbot_19200.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.cry.otp_21.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.dyndns.sven_ola.debian_kit_6.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.ethack.orwall_40.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.eu.exodus_privacy.exodusprivacy_4.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.fdroid.fdroid_1005000.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.fdroid.fdroid.privileged_2060.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.fdroid.fdroid.privileged_2070.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.fdroid.fdroid.privileged_2080.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.fedorahosted.freeotp_17.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.gnu.icecat_520610.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.jak_linux.dns66_20.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.liberty.android.freeotpplus_1.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.mozilla.fennec_fdroid_630010.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.mozilla.klar_22.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.mupen64plusae.v3.alpha_86.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.poirsouille.tinc_gui_15.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.ppsspp.ppsspp_11103.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.shadowice.flocke.andotp_20.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.shadowice.flocke.andotp_21.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.smssecure.smssecure_207.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.smssecure.smssecure_208.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.sufficientlysecure.keychain_51400.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.sufficientlysecure.keychain_52009.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.sufficientlysecure.termbot_19205.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.sufficientlysecure.viewer_2817.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.telegram.messenger_11585.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.telegram.messenger_13400.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.telegram.messenger_13580.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.woltage.irssiconnectbot_393.apk.asc
gpg --keyid-format 0xlong --verbose --verify protect.videoeditor_14.apk.asc
gpg --keyid-format 0xlong --verbose --verify ru.meefik.busybox_38.apk.asc
gpg --keyid-format 0xlong --verbose --verify uk.co.bitethebullet.android.token_5.apk.asc
gpg --keyid-format 0xlong --verbose --verify uk.co.bitethebullet.android.token_6.apk.asc
