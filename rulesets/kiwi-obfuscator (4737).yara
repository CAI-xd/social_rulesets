/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Kiwi obfuscator
    Rule id: 4737
    Created at: 2018-08-04 17:22:11
    Updated at: 2018-11-26 12:38:12
    
    Rating: #0
    Total detections: 2023
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Kiwi obfuscator"
		sample = ""

	strings:
		$key = "Kiwi__Version__Obfuscator"
		$class = "KiwiVersionEncrypter"

	condition:
		any of them
}
