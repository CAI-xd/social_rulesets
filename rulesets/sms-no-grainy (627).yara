/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lucaegitto
    Rule name: sms no grainy
    Rule id: 627
    Created at: 2015-06-23 01:06:00
    Updated at: 2015-08-06 16:00:34
    
    Rating: #0
    Total detections: 6943448
*/

import "androguard"

rule sms_malwares_nograiny
{
	meta:
		description = "SMS malwares catcher"

	condition:
		androguard.permission(/android.permission.SEND_SMS/)
		
}
