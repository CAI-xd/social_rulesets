/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Emilia
    Rule name: Chrome OpFake
    Rule id: 7361
    Created at: 2020-11-17 16:15:15
    Updated at: 2020-11-17 18:48:27
    
    Rating: #1
    Total detections: 0
*/

import "androguard"
import "file"

rule Chrome : BankTrojan
{
	meta:
		description = "This rule detects Chrome applications with Opfake malware"
		sample = "36004af3567c2f09b108dbc30458507f38ed2e2a6f462213b5f5cd783adacc7a"
		source = "https://koodous.com/apks/36004af3567c2f09b108dbc30458507f38ed2e2a6f462213b5f5cd783adacc7a"

	condition:
		file.md5("4b600ebe310a8bb21b2bce452752ddd4") or
		androguard.app_name("Chrome") and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.WRITE_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/)
		
}
