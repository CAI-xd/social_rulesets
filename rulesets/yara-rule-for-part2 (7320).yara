/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Yunana
    Rule name: Yara rule for part2
    Rule id: 7320
    Created at: 2020-11-15 18:23:36
    Updated at: 2020-11-16 14:02:37
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		sample = "54f3c7f4a79184886e8a85a743f31743a0218ae9cc2be2a5e72c6ede33a4e66e"

	condition:
	    androguard.activity(/com.google.ssearch.Dialog/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.INSTALL_PACKAGES/) and
		androguard.certificate.sha1("473DA98F656202CE4F62B221BD36A58A6F93986D") and
		androguard.url(/search.gongfu-android.com:8511\.search\.sayhi.php/) and
		not file.md5("7f5fd7b139e23bed1de5e134dda3b1ca") and 
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
