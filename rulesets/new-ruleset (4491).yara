/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jmarques
    Rule name: New Ruleset
    Rule id: 4491
    Created at: 2018-06-01 17:02:05
    Updated at: 2018-06-01 17:36:56
    
    Rating: #0
    Total detections: 726
*/

import "androguard"

rule zitmo_test
{
	meta:
		description = "Zitmo"
		samples = "be90c12ea4a9dc40557a492015164eae57002de55387c7d631324ae396f7343c"


	strings:
		$a = "ACTION_SHUTDOWN"
		$b = "BOOT_COMPLETED"
		$c = "REBOOT"
		$d = "USER_PRESENT"
		$e = "SMS_RECEIVED"
		$f = "erfolgreich"

	condition:
	    all of them and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.RECEIVE_SMS/)
		
}
