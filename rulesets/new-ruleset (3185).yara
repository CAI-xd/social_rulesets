/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: MertCanALICI
    Rule name: New Ruleset
    Rule id: 3185
    Created at: 2017-07-18 09:24:44
    Updated at: 2017-07-18 09:35:47
    
    Rating: #0
    Total detections: 45
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "FinFisher"

	condition:
		androguard.app_name("cloud service") and
		androguard.permission(/android.permission.RECORD_AUDIO/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.CALL_PHONE/) and
		androguard.permission(/android.permission/) and
		androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/)
}
