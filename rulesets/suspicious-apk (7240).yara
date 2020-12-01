/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: xayik34063
    Rule name: Suspicious APK
    Rule id: 7240
    Created at: 2020-11-10 11:20:08
    Updated at: 2020-11-10 11:51:51
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule SuspiciousAPK
{
	meta:
		description = "This rule detects a suspicious application."
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "http://one.onetwofire.com/"
		
	condition:
		androguard.package_name("com.syedjameel.tigerhuntinggameanimalshooting") and
		androguard.app_name("Video Player") and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.BIND_GET_INSTALL_REFERRER_SERVICE/) and
		androguard.permission(/android.permission.RECORD_AUDIO/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.certificate.sha1("C6811D8F4311AC584A830C3F19BC8BF9F304BF93") and
		androguard.url(/koodous\.com/) and
		not file.md5("fb94fb8f7f41088d42f0e061068b23a8") and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
