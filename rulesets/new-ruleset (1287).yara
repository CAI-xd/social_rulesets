/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: AlbertoAG
    Rule name: New Ruleset
    Rule id: 1287
    Created at: 2016-03-14 13:16:37
    Updated at: 2016-03-14 13:18:53
    
    Rating: #0
    Total detections: 0
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
