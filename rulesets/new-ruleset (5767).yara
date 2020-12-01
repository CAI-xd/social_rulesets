/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: colorfulsummer
    Rule name: New Ruleset
    Rule id: 5767
    Created at: 2019-07-18 13:28:08
    Updated at: 2019-07-26 03:43:58
    
    Rating: #0
    Total detections: 809
*/

import "androguard"
import "file"
import "cuckoo"


rule accessbt : unknown
{
		
	condition:
		androguard.permission(/android.permission.BIND_ACCESSIBILITY_SERVICE/)
		
}
