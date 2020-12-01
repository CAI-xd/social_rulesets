/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Patrick_18
    Rule name: KeepCoronaOut
    Rule id: 6825
    Created at: 2020-04-05 10:53:53
    Updated at: 2020-04-05 14:10:39
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Control
{
	meta:
		description = "A simple rule to detect the Corona Safety Mask App"

	strings:
		$a = "com.coronasafetymask.app"
		$b = "click on this link download the app and order your own face mask" 

		
	condition:
	androguard.permission(/android.permission.INTERNET/) and 
	androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and 
	androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and 			
	androguard.permission(/android.permission.SEND_SMS/) and 
	$a and 
	$b
}
