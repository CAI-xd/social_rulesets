/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: felixhoch
    Rule name: Remount system
    Rule id: 4366
    Created at: 2018-04-23 19:04:28
    Updated at: 2018-04-23 19:05:31
    
    Rating: #0
    Total detections: 938
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "remount system"

	strings:
		$a = "mount -o remount rw /system"

	condition:
		$a
		
}
