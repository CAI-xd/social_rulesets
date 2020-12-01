/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: watleuks
    Rule name: New Ruleset
    Rule id: 7404
    Created at: 2020-11-18 11:53:39
    Updated at: 2020-11-18 12:13:13
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule identity
{
	meta:
		authors = "Casper Jol and Christian Steennis"
		description = "Rule to identify apk"
		date = "18-11-2020"

	strings:
		$perm_a = "android.permission.ACCESS_NETWORK_STATE"
		$perm_b = "android.permission.GET_TASKS"
		$perm_c = "android.permission.WAKE_LOCK"
		$perm_d = "android.permission.ACCESS_WIFI_STATE"
		$perm_e = "android.permission.READ_PHONE_STATE"
		$perm_f = "android.permission.BLUETOOTH"

	condition:
		$perm_a and $perm_b and $perm_c and $perm_d and $perm_e and $perm_f 

		
}
