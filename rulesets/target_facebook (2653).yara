/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Ludovic
    Rule name: Target_Facebook
    Rule id: 2653
    Created at: 2017-05-05 14:35:45
    Updated at: 2017-05-05 14:37:20
    
    Rating: #0
    Total detections: 504403
*/

import "androguard"
import "file"
import "cuckoo"


rule Target_Facebook : official
{
	strings:
		$string_target_facebook = "com.facebook.katana"
	condition:

	($string_target_facebook)
}
