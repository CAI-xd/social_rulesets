/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Protectstar
    Rule name: Sms-Trojan
    Rule id: 6794
    Created at: 2020-03-25 13:40:26
    Updated at: 2020-03-31 07:00:06
    
    Rating: #0
    Total detections: 1074
*/

rule SMSTrojan
{
	meta:
		description = "Rule to detect SMS trojans in APK files"
		sample = "ff8ccead81eca2154cf9e891e15f52c8a154ea3aba5e62498b11fb843135837f"
		source = "http://pastebin.com/rLPux7ts"

	strings:
		$d = "com.android.install"
		
	condition:
		all of them
		
}
