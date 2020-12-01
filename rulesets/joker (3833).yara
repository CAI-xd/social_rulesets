/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Rebensk
    Rule name: Joker
    Rule id: 3833
    Created at: 2017-11-20 06:52:52
    Updated at: 2020-08-05 15:55:43
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Joker
{
	meta:
		author = "Tom_Sara"
		description = "This rule detects Joker Malware"
		
	strings:
	
	$required_1 = "getNetworkOperator"
	$required_2 = "getLine1Number"
	$required_3 = "getDeviceId"

condition:

	all of ($required_*) and 		
	androguard.activity("/com.google.android.gms.ads.AdActivity/")
		
}
