/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: anivar
    Rule name: New Ruleset
    Rule id: 5139
    Created at: 2018-12-13 07:38:57
    Updated at: 2018-12-13 07:39:17
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule PayTMActivity
{
	meta:
		description = "All PayTM SDK Apps"
