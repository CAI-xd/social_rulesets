/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: bait36
    Rule name: Gustuff test
    Rule id: 5985
    Created at: 2019-10-23 01:51:54
    Updated at: 2020-01-30 22:47:53
    
    Rating: #0
    Total detections: 108
*/

import "androguard"
import "file"
import "cuckoo"


rule gustuff: malware
{
    condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.INTERNET/) and
        androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.filter(/android.intent.action.MAIN/) and
        androguard.filter(/android.provider.Telephony.SMS_RECEIVED/) and
        androguard.filter(/android.net.conn.CONNECTIVITY_CHANGE/) and
		androguard.filter(/android.intent.action.QUICKBOOT_POWERON/) and
		androguard.filter(/android.intent.action.BOOT_COMPLETED/)
		
}
