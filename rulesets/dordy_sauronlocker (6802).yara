/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Dordy
    Rule name: Dordy_SauronLocker
    Rule id: 6802
    Created at: 2020-03-27 10:42:09
    Updated at: 2020-03-27 12:30:16
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule SauronLockerSpecialized : Dordy
{
	meta:
		description = "This rule detects the SauronLocker application, please let me know any of your ideas.. Just student work :]"
		sample = "a145ca02d3d0a0846a6dde235db9520d97efa65f7215e7cc134e6fcaf7a10ca8"

	

	condition:
		androguard.package_name("com.ins.screensaver") and
		androguard.app_name("Clash Royale Private") and
		androguard.activity(/LockActivity/i) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.receiver("com.ins.screensaver.receivers.OnBoot") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and
		androguard.service("com.ins.screensaver.services.CheckerService") and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.WRITE_CONTACTS/) and not
		androguard.certificate.sha1("2E18D3F8726B1DE631322716518FB2AEC2EBEb9E") and
		androguard.url("timei2260.myjino.ru/gateway/") and
		androguard.url("schemas.android.com/apk/res/android/")
		//cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
