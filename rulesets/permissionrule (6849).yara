/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: EfeEdipCeylani
    Rule name: PermissionRule
    Rule id: 6849
    Created at: 2020-04-17 08:23:17
    Updated at: 2020-05-28 07:47:01
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Trojan : BankBot
{
	meta:
        description = "Trojan targeting Banks"
	
	condition:
		(
			androguard.permission(/android.permission.RECEIVE_SMS/) 
			and androguard.permission(/android.permission.READ_SMS/)
			and androguard.permission(/android.permission.SEND_SMS/)
			and androguard.permission(/android.permission.ACCESS_NETWORK_STATE/)
		)
}
