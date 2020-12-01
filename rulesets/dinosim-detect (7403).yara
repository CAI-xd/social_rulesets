/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: bateman
    Rule name: DinoSim detect
    Rule id: 7403
    Created at: 2020-11-18 11:52:28
    Updated at: 2020-11-18 12:01:25
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule detect : Dinosim
{
	meta:
		description = "This rule detects the Dinosim application"
		sample = "708fa5e8d18322f92176ac0121e34dafbda231710e7d2c7b3926326b7108e400"

	condition:
		androguard.package_name("com.BitofGame.DinoSim") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.certificate.sha1("1e8b087dd8a699faa427a12844ba070b2c66218e")
		
}
