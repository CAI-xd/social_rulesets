/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: antiemulat0r
    Rule id: 3046
    Created at: 2017-06-26 14:13:28
    Updated at: 2017-07-17 17:28:48
    
    Rating: #0
    Total detections: 130098
*/

rule antiemulator
{
	meta:
		description = "Detect dumb antiemulator techniques"
		

	strings:
		$a = "google_sdk"
		$b = "generic"
		$c = "goldfish"

	condition:
		all of them
		
}
