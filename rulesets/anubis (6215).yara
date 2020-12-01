/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: EfeEdipCeylani
    Rule name: Anubis
    Rule id: 6215
    Created at: 2019-12-15 17:25:46
    Updated at: 2020-05-05 08:35:38
    
    Rating: #0
    Total detections: 39
*/

import "androguard"

rule Android_Anubis_v3
{
	meta:
		description = "Anubis newer version."

	condition:
		(androguard.filter(/android.intent.action.USER_PRESENT/i)
		and androguard.filter(/android.provider.Telephony.SMS_DELIVER/i)
		and androguard.filter(/android.provider.Telephony.SMS_RECEIVED/i))
}
