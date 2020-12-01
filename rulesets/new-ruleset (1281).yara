/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Rakshas
    Rule name: New Ruleset
    Rule id: 1281
    Created at: 2016-03-14 13:15:54
    Updated at: 2016-03-14 13:18:46
    
    Rating: #0
    Total detections: 11239
*/

import "androguard"
import "file"
import "cuckoo"


rule sandrorat
{
	meta:
		description = "This rule detects SandroRat samples"
		

	strings:
		$a = "sandrorat" nocase

	condition:
		$a
		
}
