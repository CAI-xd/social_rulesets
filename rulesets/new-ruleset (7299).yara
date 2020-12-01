/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ddoekes
    Rule name: New Ruleset
    Rule id: 7299
    Created at: 2020-11-13 10:09:47
    Updated at: 2020-11-13 10:40:06
    
    Rating: #0
    Total detections: 0
*/

rule spywareSMS
{
	meta:
		description = "This rule detects spyware send SMS"
		sample = "ff8ccead81eca2154cf9e891e15f52c8a154ea3aba5e62498b11fb843135837f"
		source = "http://pastebin.com/rLPux7ts"

	strings:
		$a = "sendMultipartTextMessage"
		$b = "l68g66qypPs="
		$c = "MY7WPp+JQGc="
		$d = "com.android.install"
		
	condition:
		all of them
		
}
