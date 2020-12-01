/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: agittainspam
    Rule name: New Ruleset
    Rule id: 7318
    Created at: 2020-11-15 16:45:56
    Updated at: 2020-11-18 12:27:41
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule dinoapp : official
{
	meta:
		description = "This rule detects the dinoapp application"
		sample = "708fa5e8d18322f92176ac0121e34dafbda231710e7d2c7b3926326b7108e400"

	condition:
		androguard.package_name("com.BitofGame.DinoSim") or
		androguard.app_name("com.BitofGame.DinoSim") or
		
		androguard.app_name("dinoapp") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.INTERNET/)
		
}
