/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: StartAll
    Rule id: 3168
    Created at: 2017-07-15 14:58:56
    Updated at: 2017-07-17 18:30:43
    
    Rating: #0
    Total detections: 1775586
*/

rule StartAll
{
	meta:
		description = "All Apps"

	strings:
		$a = "AndroidManifest.xml"
		
	condition:
		$a 
}
