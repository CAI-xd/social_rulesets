/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: drctestemail1990
    Rule name: New Ruleset
    Rule id: 7050
    Created at: 2020-08-28 15:32:36
    Updated at: 2020-08-28 15:36:09
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule coudw: amtrckr
{
	meta:
		family = "coudw"

	condition:
		androguard.url(/s\.cloudsota\.com/)
}
