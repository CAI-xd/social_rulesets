/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: knian888
    Rule name: App2 ruleset
    Rule id: 7220
    Created at: 2020-11-09 21:14:36
    Updated at: 2020-11-09 21:44:22
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule SimpLocker : official
{
	meta:
		description = "This rule detects the SimpLocker application, and applications like it"
		sample = "fd694cf5ca1dd4967ad6e8c67241114c"

	condition:
		androguard.app_name("SimpLocker") and
		androguard.activity(/android.intent.action.BOOT_COMPLETED/) and
		androguard.permission(/android.permission.INTERNET/)
}
