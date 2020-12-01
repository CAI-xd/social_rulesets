/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: thk
    Rule name: App Stores
    Rule id: 1817
    Created at: 2016-09-16 11:19:43
    Updated at: 2017-10-29 23:10:55
    
    Rating: #0
    Total detections: 590073
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
		androguard.permission(/android.permission.INSTALL_PACKAGES/)
}
