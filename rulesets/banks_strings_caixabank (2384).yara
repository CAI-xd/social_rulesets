/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: arrzuaw1
    Rule name: Banks_Strings_caixabank
    Rule id: 2384
    Created at: 2017-03-28 13:56:04
    Updated at: 2017-09-22 19:50:20
    
    Rating: #0
    Total detections: 18
*/

rule Banks_Strings_caixabank {

	strings:
		$string_1 = /caixabank\.es/
	condition:
		1 of ($string_*)
}
