/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dieee
    Rule name: Innotec Security
    Rule id: 5023
    Created at: 2018-10-30 09:48:34
    Updated at: 2019-10-24 12:39:14
    
    Rating: #0
    Total detections: 16
*/

rule Banks_Strings_inno {

	strings:
		$string_1 = /innotec\.security/
	condition:
		1 of ($string_*)
}
