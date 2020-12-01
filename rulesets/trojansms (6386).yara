/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: thatqier
    Rule name: trojanSMS
    Rule id: 6386
    Created at: 2020-02-11 18:13:22
    Updated at: 2020-02-11 18:14:30
    
    Rating: #0
    Total detections: 2899
*/

rule trojanSMS
{
	meta:
		description = "This rule detects trojan SMS"
		sample = "ff8ccead81eca2154cf9e891e15f52c8a154ea3aba5e62498b11fb843135837f"
		source = "http://pastebin.com/rLPux7ts"

	strings:
		$d = "com.android.install"
		
	condition:
		all of them
		
}
