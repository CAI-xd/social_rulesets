/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: arrzuaw1
    Rule name: Banks_Strings_bbva
    Rule id: 2376
    Created at: 2017-03-28 13:47:49
    Updated at: 2017-09-22 19:52:33
    
    Rating: #0
    Total detections: 226
*/

rule Banks_Strings_bbva {

	strings:
		$string_1 = /bbva\.es/
		$string_2 = /bbvanetcash\.com/
	condition:
		1 of ($string_*)
		
}
