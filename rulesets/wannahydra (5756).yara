/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: doopel23
    Rule name: WannaHydra
    Rule id: 5756
    Created at: 2019-07-15 07:31:40
    Updated at: 2019-07-15 07:31:43
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule android_wannahydra
{
	meta:
		description = "Yara detection for WannaHydra"
		sample = "78c9bfea25843a0274c38086f50e8b1c"


	condition:
		
	(
		(
				androguard.activity(/\.ItaActivity/) or
				androguard.activity(/\.InterSplashActivity/) or
				androguard.activity(/\.SantaSplashActivity/) or 
				androguard.activity(/\.ItaJujuActivity/) or 
				androguard.activity(/\.BBSplashActivity/) or 
				androguard.activity(/\.PhishingActivity/) or 
				androguard.activity(/\.RansoActivity/) or
				androguard.activity(/\.BBCapActivity/) or 
				androguard.activity(/\.SantaCapActivity/) or 
				androguard.activity(/\.InterCapActivity/)
		) 
			
		and
			
			(
				androguard.permission(/android.permission.SEND_SMS/) and
				androguard.permission(/android.permission.READ_CALL_LOG/) and
				androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
				androguard.permission(/android.permission.CAMERA/) and
				androguard.permission(/android.permission.RECORD_AUDIO/) and
				androguard.permission(/android.permission.READ_CONTACTS/) and
				androguard.permission(/android.permission.GET_ACCOUNTS/) and
				androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
				androguard.permission(/android.permission.INTERNET/) and
				androguard.permission(/android.permission.READ_PHONE_NUMBERS/)
				
			)

	) 	
}
