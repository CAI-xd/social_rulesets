/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: 5h1vang
    Rule name: PinkClub_Android_Locker
    Rule id: 1186
    Created at: 2016-02-08 12:42:39
    Updated at: 2016-09-29 07:36:05
    
    Rating: #1
    Total detections: 2
*/

import "androguard"

rule Android_pinkLocker
{
	meta:
		description = "Yara detection for Android Locker app named Pink Club"
		sample = "388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d"
		author = "https://twitter.com/5h1vang"
		
	strings:
		$str_1 = "arnrsiec sisani"
		$str_2 = "rhguecisoijng ts"
		$str_3 = "assets/data.db"
		$str_4 = "res/xml/device_admin_sample.xmlPK" 

	condition:
		androguard.url(/lineout\.pw/) or 
		androguard.certificate.sha1("D88B53449F6CAC93E65CA5E224A5EAD3E990921E") or
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
		all of ($str_*)
		
}
