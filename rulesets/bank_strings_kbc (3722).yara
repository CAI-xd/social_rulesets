/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TSOTIXFORCE
    Rule name: Bank_Strings_KBC
    Rule id: 3722
    Created at: 2017-10-10 10:47:36
    Updated at: 2017-10-10 10:52:00
    
    Rating: #0
    Total detections: 75
*/

rule Banks_Strings_KBC {

	strings:
		$string_1 = /online\.kbc\.ie/
		$string_2 = /kbc\.ie/
	condition:
		1 of ($string_*)
}
