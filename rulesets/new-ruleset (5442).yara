/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TSOTIXFORCE
    Rule name: New Ruleset
    Rule id: 5442
    Created at: 2019-04-10 14:42:40
    Updated at: 2019-04-10 14:48:24
    
    Rating: #0
    Total detections: 1
*/

rule BankingOnline_Strings_BOI {

	strings:
		$string_1 = /365online\.com/
		$string_2 = /businessonline\-boi\.com/
	condition:
		1 of ($string_*)
}
