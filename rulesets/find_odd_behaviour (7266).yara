/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: idp2
    Rule name: find_odd_behaviour
    Rule id: 7266
    Created at: 2020-11-12 11:58:56
    Updated at: 2020-11-12 12:16:19
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule odd_behaviours

{
	meta:
		authors = "Igor and Elize"
		date = "13 November"
		description = "This rule detects odd behaviours"
		
	strings: 
		$a = "android.intent.action.NEW_OUTGOING_CALL"
		$b = "config.cloudzad.com"
		
	condition:
		($a or $b)
}
