/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mieux
    Rule name: New Ruleset
    Rule id: 7327
    Created at: 2020-11-16 13:23:44
    Updated at: 2020-11-16 22:02:18
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
    meta:
        description = "detect potential malware"
		
    condition:
        androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and 
        androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and 
        androguard.permission(/android.permission.RECORD_AUDIO/) and 
		androguard.permission(/android.permission.INTERNET/)
}
