/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TSOTIXFORCE
    Rule name: Bank_Strings_Permanent TSB
    Rule id: 3724
    Created at: 2017-10-10 11:04:53
    Updated at: 2017-10-10 11:12:29
    
    Rating: #0
    Total detections: 32
*/

rule Banks_Strings_PermanentTSB {

	strings:
		$string_1 = /permanenttsb\.ie/
		$string_2 = /open24\.ie/
	condition:
		1 of ($string_*)
}
