/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jiexian
    Rule name: PSTATP_ADS
    Rule id: 7073
    Created at: 2020-09-28 02:52:10
    Updated at: 2020-11-04 07:47:22
    
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
		androguard.url(/pstatp\.com/) or
		androguard.url(/pglstatp-toutiao\.com/) or
		androguard.url(/pangolin-sdk-toutiao\.com/) or
		androguard.provider("com.bytedance.sdk.openadsdk.*")
}
