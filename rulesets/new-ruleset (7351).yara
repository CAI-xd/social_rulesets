/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: MYO
    Rule name: New Ruleset
    Rule id: 7351
    Created at: 2020-11-17 11:53:11
    Updated at: 2020-11-17 12:17:39
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"

 

rule SCT2{
	meta:
		description = "finds apks similar to the sample"
		sample_md5 = "73985e489d22731aefecae630d5a04d5"
	
	condition:
		androguard.permission(/.WRITE_SMS/) and
		androguard.permission(/.CALL_PHONE/) and
		androguard.permission(/.CHANGE_WIFI_STATE/) and
		androguard.permission(/.INTERNET/) and
		androguard.permission(/.READ_CONTACTS/) and
		androguard.permission(/.READ_SMS/) and
		androguard.permission(/.CHANGE_NETWORK_STATE/) and
		androguard.permission(/.SEND_SMS/) and
		androguard.permission(/.RECEIVE_MMS/) and
		not file.md5("73985e489d22731aefecae630d5a04d5")
		
}
