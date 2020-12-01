/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Tessff
    Rule name: New Ruleset
    Rule id: 7199
    Created at: 2020-11-09 15:13:39
    Updated at: 2020-11-09 16:08:22
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule CHEAT
{
	meta:
		description = "YARA rule assignment 2 Itcs, cheat APK"
		author = "Tessff"
		date = "9/11/2020"

	strings:
		$a = "READ_CONTACTS"
		$b = "SEND_SMS"
		$c = "dropper" nocase

	condition:
	
		$a and $b and $c 		
}
