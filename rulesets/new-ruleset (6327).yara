/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: maya1237
    Rule name: New Ruleset
    Rule id: 6327
    Created at: 2020-01-29 09:35:40
    Updated at: 2020-01-29 09:41:05
    
    Rating: #0
    Total detections: 12973
*/

rule koodous : official
{
	meta:
		description = "Test 2 - just yara"

	strings:
		$a =  "doubleBackToExitPressedOnce"
		$b =  "onBackPressed"
		
	condition:
		   
		   $a or $b
}
