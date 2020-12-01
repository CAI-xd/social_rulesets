/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: grvarma
    Rule name: New Ruleset
    Rule id: 2136
    Created at: 2017-01-17 07:50:28
    Updated at: 2017-01-17 07:56:17
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	

	condition:
		androguard.permission(/android.permission.WRITE_APN_SETTINGS/) and
		androguard.certificate.sha1("8399A145C14393A55AC4FCEEFB7AB4522A905139") and
		androguard.url(/koodous\.com/) and
		not file.md5("d367fd26b52353c2cce72af2435bd0d5") and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
