/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Shuanet
    Rule id: 1052
    Created at: 2015-12-09 07:47:44
    Updated at: 2015-12-09 07:48:40
    
    Rating: #0
    Total detections: 19
*/

rule shuanet:dropper
{
	meta:
		description = "This rule detects shuanet apps"
		sample = "ee8eb1c47aac2d00aa16dd8eecbae7a7bf415b3a44bc0c299ad0b58bc8e78260"

	strings:
		$a = "/system/app/System_Framework.apk"
		$b = "/system/app/System_Ad.apk"

	condition:
		all of them
		
}
