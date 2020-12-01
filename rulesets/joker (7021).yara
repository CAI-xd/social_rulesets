/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Rebensk
    Rule name: joker
    Rule id: 7021
    Created at: 2020-08-04 16:00:39
    Updated at: 2020-08-05 10:01:05
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "androguard"


rule android_joker {     
	
meta:
	description = "To Detect Joker Trojans"

   
condition:
	
        androguard.activity("com.google.android.gms.ads.AdActivity")
		
}
