/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Disane
    Rule name: AfricanScamware
    Rule id: 1649
    Created at: 2016-07-20 12:28:56
    Updated at: 2016-08-12 05:39:23
    
    Rating: #0
    Total detections: 1
*/

import "androguard"
import "file"
import "cuckoo"


rule AfricanScamware
{
	meta:
		description = "Detects scamware originating from Africa"
		family = "AfricanScamware"
		
	strings:
		$a = "http://5.79.65.207:8810"
		$b = "http://plus.google.com"
		
	condition:
		($a and $b)
		
}
