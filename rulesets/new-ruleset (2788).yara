/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: amiraguardiola
    Rule name: New Ruleset
    Rule id: 2788
    Created at: 2017-05-27 20:27:54
    Updated at: 2017-05-27 20:40:57
    
    Rating: #0
    Total detections: 0
*/

rule slempo
{

	meta:
			description = "SLEMPO"
			
	strings:
			$a = "#INTERCEPTED_SMS_START"
			$b = "#INTERCEPTED_SMS_STAR" 
			$c = "#block_numbers" 
			$d = "#wipe_data"
				
	condition:
			all of them
}
