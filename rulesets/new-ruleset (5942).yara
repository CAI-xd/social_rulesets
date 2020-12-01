/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: krsty
    Rule name: New Ruleset
    Rule id: 5942
    Created at: 2019-10-07 16:30:45
    Updated at: 2019-10-07 16:31:53
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	condition:
		androguard.url(/abcdserver\.com/) 
		
}
