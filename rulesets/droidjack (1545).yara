/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Disane
    Rule name: DroidJack
    Rule id: 1545
    Created at: 2016-06-28 06:22:12
    Updated at: 2016-07-12 10:37:35
    
    Rating: #0
    Total detections: 8985
*/

import "androguard"
import "file"
import "cuckoo"


rule DroidJack
{
	meta:
		description = "Detects only the ones that weren't obfuscated. Such as the samples like the repackaged Pokemon Go APK"
		family = "DroidJack"
		
	strings:
		$a = "droidjack"
		$b = "incoming_number"
		
	condition:
		($a and $b)
		
}
