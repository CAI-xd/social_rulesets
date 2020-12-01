/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jmmalcala
    Rule name: New Ruleset
    Rule id: 2908
    Created at: 2017-05-31 21:53:27
    Updated at: 2017-05-31 21:57:30
    
    Rating: #0
    Total detections: 1
*/

import "androguard"

rule Bankyara
{
	meta:
		description = "Regla para detectar muestra de practica4"
		

	strings:
		$string_1 = "185.62.188.32"
	
	condition:
		all of ($string_*) and
		androguard.permission(/android.permission.RECEIVE_SMS/) 
		
		}
