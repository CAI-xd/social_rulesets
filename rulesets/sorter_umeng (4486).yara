/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: sorter_umeng
    Rule id: 4486
    Created at: 2018-05-30 14:09:40
    Updated at: 2018-05-30 14:11:25
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	condition:
		androguard.url(/umeng\.info/) or
		cuckoo.network.dns_lookup(/umeng.info/) or
		cuckoo.network.http_request(/45.77.25.109/)	
		
		
}
