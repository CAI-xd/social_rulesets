/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: SetHome
    Rule id: 1524
    Created at: 2016-06-21 09:00:29
    Updated at: 2016-06-21 09:05:51
    
    Rating: #0
    Total detections: 2839
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$l = "android.intent.action.MULTI_CSC_CLEAR"
		$m = "lgeWapService.prov.persister.INSTALL_BROWSER"
		$k = "android.htc.intent.action.CUSTOMIZATION_CHANGE"

	condition:
		any of them
		
}
