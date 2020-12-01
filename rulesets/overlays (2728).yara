/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kpatsak
    Rule name: overlays
    Rule id: 2728
    Created at: 2017-05-21 12:39:25
    Updated at: 2017-05-21 12:56:44
    
    Rating: #0
    Total detections: 172
*/

import "androguard"
import "file"
import "cuckoo"


rule DetectOverlayMaleware
{
	meta:
		description = "This rule detects the many overlays"
		

	strings:
		$a = ".Telephony.SMS_RECEIVED"
		$b = ".SYSTEM_ALERT_WINDOW"
		$c = "DEVICE_ADMIN_ENABLED"
		$d = "DEVICE_ADMIN_DISABLE_REQUESTED"
        $e = "ACTION_DEVICE_ADMIN_DISABLE_REQUESTED"
		$f = ".wakeup"
		$g = "device_admin"

	condition:
		$a and $b and $c and $d and $e and $f and $g
		
}
