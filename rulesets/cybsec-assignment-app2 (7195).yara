/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: maximilionis
    Rule name: CybSec Assignment app2
    Rule id: 7195
    Created at: 2020-11-09 14:41:45
    Updated at: 2020-11-09 15:30:22
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Maliciousapk : Maliciousstrings
{
	meta:Authors = "M.Q. Romeijn & M. De Rooij"
		description = "This rule applies to malware from type DroidKungFu. We check for the package name, to check whether a fake google package is present. We focus on a couple of strings that look suspicious or relate to malicious activities. We also look if the exploit -the rage against the cage- is present. This string being present in the code is suspicious."
		sample = "881ee009e90d7d70d2802c3193190d973445d807"


	strings:
		$a = "Legacy"
		$b = "/system/app/com.google.ssearch.apk"
		$c = "imei"
		$d = "/ratc"
		$e = "/system/bin/chmod"
		

	condition:
		(androguard.package_name("com.allen.mp-1")
		or androguard.package_name("com.google.ssearch"))
		and (
		$a 
		or $b 
		or $c 
		or ($d and $e))
}
