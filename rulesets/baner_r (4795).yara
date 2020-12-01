/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: rupaliparate
    Rule name: Baner_R
    Rule id: 4795
    Created at: 2018-08-09 13:46:31
    Updated at: 2019-01-28 06:11:31
    
    Rating: #0
    Total detections: 1110
*/

import "androguard"
import "file"
import "cuckoo"


rule banker_R : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
	
		$a = "icici"
		
		$c = "setComponentEnabledSetting"
		
		$d = "android.app.action.ADD_DEVICE_ADMIN"

	condition:
	
		$a and $c and $d
		
}
