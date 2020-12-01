/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: alximw
    Rule name: New Ruleset
    Rule id: 5731
    Created at: 2019-07-11 15:26:42
    Updated at: 2019-07-11 17:59:46
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "AgentSmith"

	strings:
		$a = "/api/sdk.ad.requestAds"
		$b = "/api/sdk.ad.requestList"
		$c = "/api/sdk.ad.requestRes"
		$d = "/api/sdk.ad.requestStat"
		$e = "/api/sdk.ad.requestUpdate"
		$f = "/api/sdk.ad.uploadResult"
		$g = "com.infectionapk.patchMain"
		$h = "resa.data.encry"


	condition:
		$a or $b or $c or $d or $d or $e or $f or $g or $h
		
}
