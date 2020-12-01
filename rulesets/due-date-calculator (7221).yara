/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: s2344114
    Rule name: Due date calculator
    Rule id: 7221
    Created at: 2020-11-09 21:18:24
    Updated at: 2020-11-10 10:12:47
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the due date application, used to show all Yara rules potential"
		sample = "aa91dadd0fbcb45f5de49fba317cf25380985c33da38ab8dd6d12faccccab458"

	strings:
		$a = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}

	condition:
		androguard.package_name("com.yuvalluzon.duedatecalculator") and
		androguard.app_name("Due date calculator") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.PROCESS_OUTGOING_CALLS/) and
		androguard.permission(/com.android.browser.permission.WRITE_HISTORY_BOOKMARKS/) and
		androguard.certificate.sha1("8399A145C14393A55AC4FCEEFB7AB4522A905139") and
		androguard.url(/koodous\.com/) and
		not file.md5("099a0c178f9ed00a9b17fc30ac0601df") and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
