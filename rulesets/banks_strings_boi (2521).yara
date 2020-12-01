/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TSOTIXFORCE
    Rule name: Banks_Strings_BOI
    Rule id: 2521
    Created at: 2017-04-21 14:33:30
    Updated at: 2017-10-26 16:09:48
    
    Rating: #0
    Total detections: 492
*/

rule Banks_Strings_BOI {

	strings:
		$string_1 = /boi\.com/
		$string_2 = /365online\.com/
		$string_3 = /businessonline\-boi\.com/
		$string_4 = /bankofireland\.com/
	condition:
		1 of ($string_*)
}
