/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lisav
    Rule name: New Ruleset
    Rule id: 7122
    Created at: 2020-11-03 09:44:18
    Updated at: 2020-11-10 12:50:56
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule MobiDash : Cardgame
{
	meta:
		description = "This rule detects the MobiDash malaware embedded in the card game application"
		sample = "61b466e25d0337d968c9b3344a5a49eaf383396a"

	condition:
		androguard.package_name("com.cardgame.durak") and
		androguard.app_name("Durak") and
		androguard.activity(/com.cardgame.durak.activities.StartActivity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.certificate.sha1("61b466e25d0337d968c9b3344a5a49eaf383396a") and
		not file.md5("474558b94a0c84fa29a355a6ba96edfa ") and 
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
