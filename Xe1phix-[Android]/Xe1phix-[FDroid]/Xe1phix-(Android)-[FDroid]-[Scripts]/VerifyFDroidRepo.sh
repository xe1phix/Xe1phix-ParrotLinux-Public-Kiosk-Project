#!/bin/sh
## VerifyFDroidRepo.sh
## ===================================== ##
## 
## gpg --full-gen-key --enable-large-rsa
## ------------------------------------------------------------------------------------------------------------------------------------------ ##
## gpg --verbose --keyid-format 0xlong --keyserver hkp://pool.sks-keyservers.net --recv-keys 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
## gpg --fingerprint --with-subkey-fingerprint0x37D2C98789D8311948394E3E41E7044E1DBA2E89
## gpg --edit-key 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
## gpg --keyid-format 0xlong --verbose --lsign 0x37D2C98789D8311948394E3E41E7044E1DBA2E89
## ------------------------------------------------------------------------------------------------------------------------------------------ ##
## 
## GPG signing key: “F-Droid <admin@f-droid.org>”
## ---------------------------------------------------------------------------- ##
## Primary key fingerprint: 37D2 C987 89D8 3119 4839 4E3E 41E7 044E 1DBA 2E89
## Subkey fingerprint: 802A 9799 0161 1234 6E1F EFF4 7A02 9E54 DD5D CE7A
## ---------------------------------------------------------------------------- ##
## cp -v VerifyFDroidRepo.sh Downloads/FDroid
## cd Downloads/FDroid/
## chmod +x VerifyFDroidRepo.sh
## ./VerifyFDroidRepo.sh 
## 
## gpg --verify-files
## gpg --multifile --verify 
## gpg --multifile --encrypt 
## gpg --multifile --decrypt 

## ===================================== ##

gpg --keyid-format 0xlong --verbose --verify dev.ukanth.ufirewall_15979.apk.asc
gpg --keyid-format 0xlong --verbose --verify app.librenews.io.librenews_5.apk.asc
gpg --keyid-format 0xlong --verbose --verify be.uhasselt.privacypolice_13.apk.asc
gpg --keyid-format 0xlong --verbose --verify chromiumupdater.bamless.com.chromiumsweupdater_6.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.adonai.manman_171.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.amaze.filemanager_63.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.anddevw.getchromium_20170318.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.android.keepass_164.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.briankhuu.nfcmessageboard_16.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.catchingnow.tinyclipboardmanager_57.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.commit451.gitlab_2050000.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.eolwral.osmonitor_90.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.fsck.k9_23271.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.github.yeriomin.yalpstore_32.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.majeur.applicationsinfo_7.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.mantz_it.rfanalyzer_1303.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.menny.android.anysoftkeyboard_2658.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.mrbimc.selinux_20171031.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.nhellfire.kerneladiutor_246.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.notecryptpro_18.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.pavelsikun.runinbackgroundpermissionsetter_8.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.redirectapps.tvkill_21.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.stoutner.privacybrowser.standard_29.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.termux_59.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.yubico.yubiclip_5.apk.asc
gpg --keyid-format 0xlong --verbose --verify com.yubico.yubioath_34.apk.asc
gpg --keyid-format 0xlong --verbose --verify crl.pem
gpg --keyid-format 0xlong --verbose --verify cx.ring_99.apk.asc
gpg --keyid-format 0xlong --verbose --verify cz.eutopia.snooperstopper_4.apk.asc
gpg --keyid-format 0xlong --verbose --verify de.blinkt.openvpn_153.apk.asc
gpg --keyid-format 0xlong --verbose --verify de.srlabs.snoopsnitch_17.apk.asc
gpg --keyid-format 0xlong --verbose --verify de.t_dankworth.secscanqr_4.apk.asc
gpg --keyid-format 0xlong --verbose --verify dev.ukanth.ufirewall_15979.apk.asc
gpg --keyid-format 0xlong --verbose --verify dmusiolik.pijaret_9.apk.asc
gpg --keyid-format 0xlong --verbose --verify eu.faircode.netguard_2016072421.apk.asc
gpg --keyid-format 0xlong --verbose --verify eu.siacs.conversations_247.apk.asc
gpg --keyid-format 0xlong --verbose --verify FDroid.apk.asc
gpg --keyid-format 0xlong --verbose --verify fr.keuse.rightsalert_3.apk.asc
gpg --keyid-format 0xlong --verbose --verify fr.neamar.kiss_102.apk.asc
gpg --keyid-format 0xlong --verbose --verify indrora.atomic_21.apk.asc
gpg --keyid-format 0xlong --verbose --verify info.guardianproject.browser_7010.apk.asc
gpg --keyid-format 0xlong --verbose --verify info.guardianproject.cacert_4.apk.asc
gpg --keyid-format 0xlong --verbose --verify info.guardianproject.checkey_101.apk.asc
gpg --keyid-format 0xlong --verbose --verify info.guardianproject.pixelknot_101.apk.asc
gpg --keyid-format 0xlong --verbose --verify info.guardianproject.ripple_83.apk.asc
gpg --keyid-format 0xlong --verbose --verify io.mrarm.irc_5.apk.asc
gpg --keyid-format 0xlong --verbose --verify jackpal.androidterm_72.apk.asc
gpg --keyid-format 0xlong --verbose --verify jp.forkhub_1020800.apk.asc
gpg --keyid-format 0xlong --verbose --verify net.bierbaumer.otp_authenticator_3.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.adaway_60.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.bitbatzen.wlanscanner_1.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.blokada.alarm_29.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.cipherdyne.fwknop2_32.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.connectbot_19200.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.cry.otp_21.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.csploit.android_6.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.dyndns.sven_ola.debian_kit_6.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.ethack.orwall_40.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.fdroid.fdroid.privileged_2070.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.fedorahosted.freeotp_17.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.gnu.icecat_520411.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.jak_linux.dns66_20.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.jtb.alogcat_43.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.kiwix.kiwixmobile_47.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.legtux.m_316k.fortune_2.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.linphone_3311.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.microg.nlp_20187.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.mozilla.fennec_fdroid_570110.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.mozilla.klar_16.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.ppsspp.ppsspp_11103.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.shadowice.flocke.andotp_12.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.smssecure.smssecure_205.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.sufficientlysecure.keychain_48002.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.telegram.messenger_11555.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.woltage.irssiconnectbot_393.apk.asc
gpg --keyid-format 0xlong --verbose --verify org.yaaic_13.apk.asc
gpg --keyid-format 0xlong --verbose --verify ru.meefik.busybox_34.apk.asc
gpg --keyid-format 0xlong --verbose --verify se.anyro.nfc_reader_15.apk.asc
gpg --keyid-format 0xlong --verbose --verify sks-keyservers.netCA.pem.asc
gpg --keyid-format 0xlong --verbose --verify subreddit.android.appstore_7100.apk.asc
gpg --keyid-format 0xlong --verbose --verify uk.co.ashtonbrsc.android.intentintercept_224.apk.asc

