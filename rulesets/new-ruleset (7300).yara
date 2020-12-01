/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Matthijs
    Rule name: New Ruleset
    Rule id: 7300
    Created at: 2020-11-13 10:41:06
    Updated at: 2020-11-13 11:11:59
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Durak : MobiDash
{
	meta:
		description = "This rule detects cardgame durak, MobiDash malware"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "mobi.dash.extras.Action_Bootstraped"

	condition:
		androguard.package_name("com.cardgame.durak") and
		androguard.app_name("durak") and
		androguard.filter(/SCREEN_OFF/) and
		androguard.filter(/USER_PRESENT/) and
		androguard.certificate.sha1("b41d8296242c6395eee9e5aa7b2c626a208a7acce979bc37f6cb7ec5e777665a") and 
		$a 	
}
