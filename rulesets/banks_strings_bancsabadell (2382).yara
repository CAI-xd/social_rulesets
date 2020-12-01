/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: arrzuaw1
    Rule name: Banks_Strings_bancsabadell
    Rule id: 2382
    Created at: 2017-03-28 13:54:58
    Updated at: 2017-09-22 19:50:38
    
    Rating: #0
    Total detections: 45
*/

rule Banks_Strings_bancsabadell {

	strings:
		$string_1 = /bancsabadell\.com/
	condition:
		1 of ($string_*)
}
