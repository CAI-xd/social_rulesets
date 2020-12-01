/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Sekoeritie
    Rule name: DroidKungFu1
    Rule id: 7194
    Created at: 2020-11-09 14:40:44
    Updated at: 2020-11-09 14:54:56
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule DroidKungFu
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "881ee009e90d7d70d2802c3193190d973445d807"

	strings:
		$trigger = "adb pull /data/data/com.allen.mp/shared_prefs/sstimestamp.xml"
		$j1 = "onCreate.java"
		$j2 = "updateInfo.java"
		$j3 = "cpLegacyRes.java"
		$j4 = "decrypt.java"
		$j5 = "doExecuteTask.java"
		$j6 = "deleteApp.java"

	condition:
		androguard.package_name("com.koodous.android") and
		androguard.app_name("DroidKungFu1") and
		$trigger and
		$j1 and
		$j2 and
		$j3 and
		$j4 and
		$j5 and
		$j6 and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/)
		
}
