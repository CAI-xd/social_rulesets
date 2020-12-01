/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: arrzuaw1
    Rule name: Banks_Strings_bankia
    Rule id: 2380
    Created at: 2017-03-28 13:53:46
    Updated at: 2017-09-22 19:50:52
    
    Rating: #0
    Total detections: 201
*/

rule Banks_Strings_bankia {

	strings:
		$string_1 = /bankia\.es/
	condition:
		1 of ($string_*)
}
