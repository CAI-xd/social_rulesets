/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dgarcia
    Rule name: SMS_sender
    Rule id: 2519
    Created at: 2017-04-21 13:53:57
    Updated at: 2017-04-21 14:00:10
    
    Rating: #0
    Total detections: 465353
*/

import "androguard"
import "file"
import "cuckoo"


rule sms_suspect
{
	meta:
		description = "This rule detects APKs with SMS (write & send) permissions"

	condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.WRITE_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.RECEIVE_SMS/)
}
