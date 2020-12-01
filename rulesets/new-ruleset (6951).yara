/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: riffraff
    Rule name: New Ruleset
    Rule id: 6951
    Created at: 2020-05-27 09:39:59
    Updated at: 2020-05-27 09:41:58
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule mspy : internalstring
{
	meta:
		desc = "a$ is string we found in the sample"
		sample = "8074902e0abbfcff2f23c6f6e47384ae15bc9e1aa1cabc0cc300604cdac66879"

	strings:
		$a = "MSPY_PACKAGE_NAME"

	condition:
		$a 
		
}
