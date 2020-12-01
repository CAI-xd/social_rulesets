/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Plastic-Shaman
    Rule name: New Ruleset
    Rule id: 7304
    Created at: 2020-11-13 11:39:59
    Updated at: 2020-11-17 20:23:26
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects when application tries to gain admin rights and wants to do something with SMS"
		
	
	strings:
		$a = "android.app.action.ADD_DEVICE_ADMIN"
		$b = "android.app.extra.DEVICE_ADMIN" nocase
		$c = "/private/tuk_tuk.php"
	condition:
		($a and $b) and (androguard.permission(/RECEIVE_SMS/) or androguard.permission(/READ_SMS/) or androguard.permission(/SEND_SMS/) or $c) 
}
