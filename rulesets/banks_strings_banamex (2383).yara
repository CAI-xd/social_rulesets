/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: arrzuaw1
    Rule name: Banks_Strings_banamex
    Rule id: 2383
    Created at: 2017-03-28 13:55:22
    Updated at: 2017-09-22 19:50:29
    
    Rating: #0
    Total detections: 62
*/

rule Banks_Strings_banamex {

	strings:
		$string_1 = /banamex\.com/
	condition:
		1 of ($string_*)
}
