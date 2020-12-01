/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: annafelicia
    Rule name: New Ruleset
    Rule id: 7134
    Created at: 2020-11-04 11:33:19
    Updated at: 2020-11-04 11:54:38
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule Cajino
{
	meta:
		Author= "Anna and Felicia"
		email = "s1958410@vuw.leidenuniv.nl"
		reference= "https://www.virustotal.com/gui/file/767ae060d756dff8dcf3e477066d240e7cd861a525b2b75cb914cdace94e76b3/"
		sample = "c1a3e1a372df344b138e2edb541fdc1d7c1842726ca85a38137ca902a0e5dc6b"
		date = "04/11/2020"
		description = "This is a basic YARA rule for CEO fraud."

	strings:
		$a = "TitaniumCore"
		$b = "Landroid/app/IntentService"

	condition:
		($a or $b) or
		androguard.package_name("com.Titanium.Gloves") or
	  	androguard.certificate.sha1("db27bc861665495329fb93df30017e24ddda8d27")

}
