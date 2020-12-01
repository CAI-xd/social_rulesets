/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: osiris
    Rule name: ShadowVoice
    Rule id: 6154
    Created at: 2019-11-29 07:44:05
    Updated at: 2019-12-06 08:02:27
    
    Rating: #1
    Total detections: 2
*/

import "androguard"
import "file"
import "cuckoo"


rule redrabbit : ShadowVoice
{
	meta:
		description = "This rule detects the voicephishing app targeted for Korean"
	condition:
		androguard.package_name("com.red.rabbit") and
		androguard.permission(/android.permission.PROCESS_OUTGOING_CALL/)
}

rule redrainbow : ShadowVoice
{
	meta:
		description = "This rule detects the voicephishing app targeted for Korean"
	condition:
		androguard.package_name("com.red.rainbow") and
		androguard.permission(/android.permission.PROCESS_OUTGOING_CALL/)
}
