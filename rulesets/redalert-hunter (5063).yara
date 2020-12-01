/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: doopel23
    Rule name: RedAlert Hunter
    Rule id: 5063
    Created at: 2018-11-16 12:04:11
    Updated at: 2018-11-16 12:04:37
    
    Rating: #0
    Total detections: 0
*/

rule redalertJAR {

	strings:
		$string_1 = /http:\/\/\S+:7878/
		$string_2 = "twitter.com"
		$string_4 = "Enable security protection"
		$string_5 = "timeapi.org"
	condition:
		all of ($string_*)
}


rule readAlertNEW {
	strings:
		$string_1 = "twwitter.com"
		$string_2 = /http:\/\/\S+:7878/
		$string_4 = "utc/now?%5CD"
	condition:
		all of ($string_*)
}
