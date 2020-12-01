/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Sekoeritie
    Rule name: apk 1
    Rule id: 7181
    Created at: 2020-11-09 10:43:38
    Updated at: 2020-11-09 14:47:14
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule writing_adware
{
	meta:
		author = "Group 30"
		data = "9-11-2020"
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "d96bad641cad063c1869b06d9497a97c216eecc460245b0ea8ee6ab1f9e1ae56"

	strings:
		$start = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}

	condition:
		androguard.package_name("org.mightyfrog.android.simplenotepad") and
		androguard.app_name("snacks.recipes.tutorials.videos") and
		androguard.activity(/com.ghrataneomwalide06.matbakhomwalid2017free06.sdk.activity.StartActivity/) and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.certificate.sha1("51df3fb7839d894fa941abfc0832283308cfb") and
		androguard.url(/koodous\.com/) and
		not file.md5("d367fd26b52353c2cce72af2435bd0d5") and 
		$start and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/)
		
}
