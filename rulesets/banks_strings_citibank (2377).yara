/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: arrzuaw1
    Rule name: Banks_Strings_citibank
    Rule id: 2377
    Created at: 2017-03-28 13:51:30
    Updated at: 2017-09-22 19:50:08
    
    Rating: #0
    Total detections: 1538
*/

rule Banks_Strings_citibank {

	strings:
		$string_1 = /citibank\.com/
	condition:
		1 of ($string_*)
		
}
