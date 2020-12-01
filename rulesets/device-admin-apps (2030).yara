/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: thk
    Rule name: Device Admin apps
    Rule id: 2030
    Created at: 2016-12-13 14:10:22
    Updated at: 2017-10-29 23:11:02
    
    Rating: #0
    Total detections: 22676
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
		androguard.permission(/android.permission.BIND_DEVICE_ADMIN/)
}
