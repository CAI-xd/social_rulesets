/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ASG
    Rule name: SamsungPay
    Rule id: 7396
    Created at: 2020-11-18 10:39:35
    Updated at: 2020-11-18 11:06:18
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule samsungpay
{
	meta:
		description = "This rule detects the malicious Samsung Pay application"
		sample = "b58d9f3f1fb543fd645cd00689254f52a4c2a97a0b7c88ef219480636710e6cd"

	strings:
		$a = "https://support.mobile-tracker-free.com/hc/articles/360008476074-Xiaomi-Android-Guide"

	condition:
		androguard.package_name("mob.service.parental2020") and
		androguard.app_name("Samsung Pay") and
		androguard.activity(/ConfigPhoneActivity/i) and
		androguard.permission(/android.permission.READ_CALL_LOG/) and
		androguard.certificate.sha1("61ed377e85d386a8dfee6b864bd85b0bfaa5af81") and
		androguard.url(/app-measurement\.com/) and
		not file.md5("d367fd26b52353c2cce72af2435bd0d5") and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/)
		
}
