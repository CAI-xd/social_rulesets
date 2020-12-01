/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: test_CerebrusDecrypted
    Rule id: 6416
    Created at: 2020-02-25 03:29:55
    Updated at: 2020-02-25 03:32:07
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule test_CerebrusDecrypted
{
	meta:
		description = "This rule, if works, should detected decrypted cerberus apk files" 
		
	strings:
		$a1 = "patch.ring0.run"
		$a2 = "143523#"
		$a3 = "enabled_accessibility_services"
		$a4 = "android.app.role.SMS"
		$a5 = "device_policy"
		$a6 = "Download Module:"

	condition:
        all of ($a*)

		
}
