/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: 0xAnthyx
    Rule name: Chrome Banking Trojan
    Rule id: 6813
    Created at: 2020-03-31 14:20:57
    Updated at: 2020-03-31 14:29:11
    
    Rating: #0
    Total detections: 3
*/

import "androguard"
import "file"

rule Chrome : BankTrojan
{
	meta:
		description = "This rule will detect Chrome impersonation application with Banker.C Trojan in it"
		sample = "dfe24acdce1f224d055b08de574d8931dac2d791f8294d9660bb929b24e80130"
		source = "https://koodous.com/apks/dfe24acdce1f224d055b08de574d8931dac2d791f8294d9660bb929b24e80130"
		
	strings:
		$S1_1 = "asc2V0Q29tcG9u"
		$S1_2 = "ZW50RW5hYmxlZFNldHRpbmc="
		
	condition:
		all of ($S1_*) or
		androguard.package_name("com.kaiw.hlhf") and
		file.md5("06b5812e2f940f3a349fd923dca68ff9") and
		androguard.permission(/ubhizn.yglrdc.sjxbvf/) or
		androguard.permission(/nxdbbcfl.zouyua.mbxsztft/) or
		androguard.permission(/nfcezfm.zbsfmav.vkzxbhb/) and
		androguard.permission(/android.permission.android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.WRITE_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.WAKE_LOCK/) and 
		androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) or
		androguard.activity("/getComponentEnabledSetting/") or
		androguard.url(/tyhdaou\.blogspot/) or
		androguard.url(/128\.1\.223\.222/)
}
