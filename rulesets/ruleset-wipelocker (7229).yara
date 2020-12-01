/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Bvlampe
    Rule name: Ruleset: WipeLocker
    Rule id: 7229
    Created at: 2020-11-10 09:29:43
    Updated at: 2020-11-10 10:23:15
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the WipeLocker malware"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "new DeviceManager().activateDeviceAdmin((Activity)this, 1000);"
		$a_wide = "new DeviceManager().activateDeviceAdmin((Activity)this, 1000);" wide
		$b = "HEY!!! "
		$b_wide = "HEY!!! " wide

	condition:
		androguard.app_name("Angry Birds Transformers") and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		not file.md5("d367fd26b52353c2cce72af2435bd0d5") and 
		($a or $a_wide) and ($b or $b_wide) and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
