/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TSOTIXFORCE
    Rule name: Bank_Strings_UlsterBank
    Rule id: 3723
    Created at: 2017-10-10 10:52:16
    Updated at: 2017-10-10 11:04:47
    
    Rating: #0
    Total detections: 81
*/

rule Banks_Strings_UlsterBank {

	strings:
		$string_1 = /digital\.ulsterbank\.ie/
		$string_2 = /ulsterbankanytimebanking\.ie/
		$string_3 = /ulsterbank\.ie/
		$string_4 = /cardsonline\-commercial\.com/
		$string_5 = /bankline\.ulsterbank\.ie/
	condition:
		1 of ($string_*)
}
