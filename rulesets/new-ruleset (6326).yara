/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: maya1237
    Rule name: New Ruleset
    Rule id: 6326
    Created at: 2020-01-28 17:59:10
    Updated at: 2020-01-29 09:34:56
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


 
	meta: 
	description = "This rule try to detect Apps with onBackPressed and      doubleBackToExitPressedOnce pernmissions "

	
	condition:
		androguard.permission(/onBackPressed/)
		or
		androguard.permission(/doubleBackToExitPressedOnce/)
