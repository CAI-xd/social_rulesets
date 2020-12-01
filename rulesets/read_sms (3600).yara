/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yonatangot
    Rule name: read_sms
    Rule id: 3600
    Created at: 2017-09-18 07:42:38
    Updated at: 2017-09-18 11:18:10
    
    Rating: #0
    Total detections: 301581
*/

import "androguard"
import "file"
import "cuckoo"


rule readsms
{
	meta:
		description = "This rule detects read_sms"

	condition:
		androguard.permission(/android.permission.READ_SMS/)
}
