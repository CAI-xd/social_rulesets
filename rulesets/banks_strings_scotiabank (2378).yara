/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: arrzuaw1
    Rule name: Banks_Strings_scotiabank
    Rule id: 2378
    Created at: 2017-03-28 13:52:22
    Updated at: 2017-09-22 19:51:05
    
    Rating: #0
    Total detections: 1019
*/

rule Banks_Strings_scotiabank {

	strings:
		$string_1 = /scotiabank\.com/
	condition:
		1 of ($string_*)
		
}
