/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: bryTesting
    Rule name: SendSMS_NoAuth
    Rule id: 2632
    Created at: 2017-05-04 13:30:30
    Updated at: 2017-06-15 14:48:33
    
    Rating: #0
    Total detections: 2728
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule is checking for SMS sending without creds/authentication"

	condition:

		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.CHANGE_CONFIGURATION/) and
		not androguard.permission(/android.permission.AUTHENTICATE_ACCOUNTS/) and
		not androguard.permission(/android.permission.USE_CREDENTIALS/) and
		not androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		not androguard.permission(/android.permission.BLUETOOTH_ADMIN/)

		
}
