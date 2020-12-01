/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Ludovic
    Rule name: Target_Instagram
    Rule id: 2655
    Created at: 2017-05-05 14:40:01
    Updated at: 2017-05-05 14:41:02
    
    Rating: #0
    Total detections: 107181
*/

import "androguard"
import "file"
import "cuckoo"


rule Target_Instagram : official
{
	strings:
		$string_target_fbmessenger = "com.instagram.android"
	condition:

	($string_target_fbmessenger)
}
