/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: arrzuaw1
    Rule name: Banks_Strings_lacaixa
    Rule id: 2381
    Created at: 2017-03-28 13:54:25
    Updated at: 2017-09-22 19:50:45
    
    Rating: #0
    Total detections: 156
*/

rule Banks_Strings_lacaixa {

	strings:
		$string_1 = /lacaixa\.es/
	condition:
		1 of ($string_*)
}
