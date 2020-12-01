/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: arrzuaw1
    Rule name: redalert
    Rule id: 3652
    Created at: 2017-09-22 19:48:03
    Updated at: 2017-09-26 21:12:48
    
    Rating: #0
    Total detections: 717
*/

rule redalert {

	strings:
		$string_1 = /http:\/\/\S+:7878/
		$string_2 = /wroted data base64/
		$string_3 = /templates_names/
	condition:
		1 of ($string_*)
}
