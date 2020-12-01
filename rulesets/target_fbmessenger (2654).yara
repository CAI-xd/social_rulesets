/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Ludovic
    Rule name: Target_FBMessenger
    Rule id: 2654
    Created at: 2017-05-05 14:37:33
    Updated at: 2017-05-05 14:39:15
    
    Rating: #0
    Total detections: 319492
*/

import "androguard"
import "file"
import "cuckoo"


rule Target_FBMessenger : official
{
	strings:
		$string_target_fbmessenger = "com.facebook.orca"
	condition:

	($string_target_fbmessenger)
}
