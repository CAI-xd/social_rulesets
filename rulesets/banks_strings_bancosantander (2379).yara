/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: arrzuaw1
    Rule name: Banks_Strings_bancosantander
    Rule id: 2379
    Created at: 2017-03-28 13:52:59
    Updated at: 2017-09-22 19:50:59
    
    Rating: #0
    Total detections: 20
*/

rule Banks_Strings_bancosantander {

	strings:
		$string_1 = /bancosantander\.es/
	condition:
		1 of ($string_*)
		
}
