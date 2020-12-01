/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: rodriguezrey
    Rule name: Admin&SMS
    Rule id: 3262
    Created at: 2017-07-28 09:16:36
    Updated at: 2017-07-31 11:07:10
    
    Rating: #0
    Total detections: 4766
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
		androguard.permission(/android.permission.BIND_DEVICE_ADMIN/) and
		androguard.permission(/android.permission.RECEIVE_SMS/)
		
}
