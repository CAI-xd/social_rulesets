/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: doopel23
    Rule name: BankBot Hunter
    Rule id: 5056
    Created at: 2018-11-12 16:00:20
    Updated at: 2019-01-18 10:52:41
    
    Rating: #0
    Total detections: 112
*/

import "androguard"
import "droidbox"

rule bankbot
{
	meta:
		description = "This rule detects the bankbot app based on various info"
		family = "bankbot"

	strings:
		$s1 = /res\/layout\/[a-zA-Z\d!@#$%&*]{3}.xmlPK/
		$s2 = "META-INF/RSASIG.RSAPK"
		$s3 = "META-INF/RSASIG.SFPK"
		$s4 = "META-INF/MANIFEST.MFPK"

	condition:
		any of ($s*) 
		and
		(
			androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
			androguard.permission(/android.permission.RECEIVE_SMS/) and
			androguard.permission(/android.permission.READ_SMS/) and
			androguard.permission(/android.permission.INTERNET/) and
			androguard.permission(/android.permission.WRITE_SMS/) and
			androguard.permission(/android.permission.CALL_PHONE/) and
			androguard.permission(/android.permission.RECORD_AUDIO/) and
			androguard.permission(/android.permission.GET_TASKS/) and
			androguard.permission(/android.permission.READ_CONTACTS/)
		)
		and
		(
		droidbox.written.data(/spamSMS/i) or
		droidbox.written.data(/indexSMSSPAM/i) or
		droidbox.written.data(/RequestINJ/i) or
		droidbox.written.data(/VNC_Start_NEW/i) or
		droidbox.written.data(/keylogger/i) or
		droidbox.written.data(/shared_prefs\/set\.xml/i) or
		droidbox.read.data(/app_files\/?.*\.[jar|dex]/i)
		)
}
