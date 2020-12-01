/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: devploit
    Rule name: Fortnite: Fake
    Rule id: 4999
    Created at: 2018-10-18 14:49:31
    Updated at: 2018-10-18 14:52:28
    
    Rating: #0
    Total detections: 47
*/

import "androguard"


rule Fornite: fake
{
	meta:
		description = "This rule detects Fortnite Fake APKs"
		sample = ""

	condition:
		(androguard.package_name("com.epicgames.portal") or androguard.app_name("Fortnite")) and not
		androguard.certificate.sha1("707566F8B09B4C8BFD772E1B536D581F19BC3012")
}
