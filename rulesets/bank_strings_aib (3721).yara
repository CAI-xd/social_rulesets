/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TSOTIXFORCE
    Rule name: Bank_Strings_AIB
    Rule id: 3721
    Created at: 2017-10-10 10:35:24
    Updated at: 2017-10-10 10:47:03
    
    Rating: #0
    Total detections: 221
*/

rule Banks_Strings_AIB {

	strings:
		$string_1 = /onlinebanking\.aib\.ie/
		$string_2 = /business\.aib\.ie/
		$string_3 = /aib\.ie/
	condition:
		1 of ($string_*)
}
