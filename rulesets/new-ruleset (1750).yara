/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: New Ruleset
    Rule id: 1750
    Created at: 2016-08-17 18:52:16
    Updated at: 2016-08-17 19:01:00
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule shuanet : adWare
{
	meta:
		description = "This rule detects shuanet aggresive malware"
		
	condition:
		androguard.service(/com\/boyaa\/push/) and
		androguard.receiver(/orp\/frame\/shuanet\/abs/)
		
		
}

rule shuanet2 : adWare
{
	meta:
		description = "This rule detects shuanet aggresive malware"
		
	condition:
		androguard.service("com/boyaa/push/NotifyCenterAIDL") and
		androguard.receiver("orp/frame/shuanet/abs/DataReciver")
		
}
