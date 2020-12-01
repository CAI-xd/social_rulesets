/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: leooel
    Rule name: FindSimilar
    Rule id: 7324
    Created at: 2020-11-15 21:58:38
    Updated at: 2020-11-15 22:14:01
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule findsimilar : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	condition:
		androguard.package_name("dglf.qaejy.sxfsr") or
		androguard.app_name("Chrome") or
		androguard.activity(/Details_Activity/i) or
		androguard.permission(/android.permission.SMS/) or
		file.md5("8bdba6763092a3741170a59e3badeee1") or  
		file.sha256("92d21ea836f53673e81678fef1e243500cd0c9bd0180662618b2de03f714560e") or 
		file.sha1("53cbdaffb5d044e49b9cebf676f0967904fbc0e3")	
}
