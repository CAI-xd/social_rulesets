/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: sec2
    Rule name: Shushiplace Rule
    Rule id: 7376
    Created at: 2020-11-17 19:32:07
    Updated at: 2020-11-18 11:16:57
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "hash"

rule shishiplace
{
	meta:
		description = "This  rule detects the shushiplace apk and similar types of apk's."
	
	condition:
		file.sha265("ab0c364ff6b1678ee85fea0437ff563f51c63332a2cf3ef4c07ac9112dad8deb") or
		(
		androguard.package_name("com.appswiz.shushiplace") and
		androguard.certificate.sha1("678776B603C4D2D44E596F16E08C2E2C1859D208") and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.certificate.sha1("678776B603C4D2D44E596F16E08C2E2C1859D208")
		)
		
		
		
}
