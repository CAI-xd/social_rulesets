/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Fenna
    Rule name: New Ruleset
    Rule id: 7114
    Created at: 2020-11-02 14:08:41
    Updated at: 2020-11-09 14:50:23
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"


rule CallRecorder
{
	meta:
		description = "This rule detects the koodous application Call Recorder."
		sample = "0ba20f8fa969ba0622c739b6570c30a4fe4da40ea8dbd8c86cd3696b476f1179"

	condition:
		androguard.package_name("com.tooskagroup1400.callrecordvoice") and
		androguard.app_name("Call Recorder") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.permission(/com.tooskagroup1400.callrecordvoice.permission.C2D_MESSAGE/) and
		androguard.url(/cafebazaar\.ir/) and 
		androguard.activity("com.tooskagroup1400.callrecordvoice.MainActivity") and 
		androguard.activity("com.tooskagroup1400.callrecordvoice.AlertActivity") and 
		androguard.receiver("co.ronash.pushe.receiver.BootAndScreenReceiver") and 
		not file.md5("d367fd26b52353c2cce72af2435bd0d5")
		
}
