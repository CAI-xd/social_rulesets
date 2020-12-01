/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: sorter_ckservice_QD_SUBID
    Rule id: 4719
    Created at: 2018-08-02 02:03:59
    Updated at: 2018-08-06 09:08:12
    
    Rating: #0
    Total detections: 41
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
		$ = "QD_SUBID"
		$ = "ASt20180731"
		$ = "bHgSwitch"
		$ = "HeguSDK"
		$ = "sviptodo"
		$ = "android.intent.ss.rbcm"
		$ = "adv.google-global.com"
		$ = "moast.zip"
		$ = "android.intent.start.dta"
		$ = "instance_taskcontainer"
		$ = "android.intent.action.stopsp"
		$ = "aHR0cHM6Ly9hcGkubml1bW9iaS5jb20vYWEvbmM="
		$ = "api.jsian.com"
		
	condition:
		any of them or
		androguard.url(/google-global.com/) or
		androguard.url("198.11.177.209") or
		androguard.url("47.254.56.0") or
		androguard.url("47.88.10.168") or
		androguard.url(/adv.gmscenter.org/) or
		androguard.url(/adv.google-global.com/) or
		androguard.url(/api.jsian.com/) or
		androguard.url(/rcv.ilabtap.com/) or
		cuckoo.network.dns_lookup(/google-global.com/) or
		cuckoo.network.dns_lookup(/adv.gmscenter.org/) or
		cuckoo.network.dns_lookup(/jsian.com/)
		
}
