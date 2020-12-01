/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pr3w
    Rule name: AndroBot
    Rule id: 3618
    Created at: 2017-09-20 16:37:37
    Updated at: 2017-09-28 19:14:15
    
    Rating: #0
    Total detections: 1
*/

rule Androbot
{
	meta:
		description = "https://info.phishlabs.com/blog/bankbot-continues-its-evolution-as-agressivex-androbot"


	strings:
		$s1 = "/core/inject.php?type="
		$s2 = "/private/add_log.php"
		$s3 = "/core/functions.php "

	condition:
		2 of ($s*)
		
}
