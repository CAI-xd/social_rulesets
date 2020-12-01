/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: vilena1
    Rule name: New Ruleset
    Rule id: 7011
    Created at: 2020-07-24 15:13:01
    Updated at: 2020-07-24 15:14:30
    
    Rating: #0
    Total detections: 0
*/

rule Minergate
{
	meta:
		description = "This rule detects the Minergate string"

	strings:
		$a = "minergate.com"

	condition:
		$a 
		
}
