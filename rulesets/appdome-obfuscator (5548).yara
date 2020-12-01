/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Appdome obfuscator
    Rule id: 5548
    Created at: 2019-05-19 16:57:34
    Updated at: 2019-12-26 01:25:27
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Appdome"

	strings:
		$ = "APPDOME_INTERNAL_GOOD_FSQUEUE"
		$ = "res/drawable/splash_appdome.png"
		$ = "_appdome_splash"
		$ = "AppdomeInternalAppdomeSSOMessage"
		$ = "AppdomeSecurityAlert"
		$ = "APPDOME_INTERNAL_EXPIRE_ON_POLICY"
		$ = "X-APPDOME-MARKEDr"
		$ = "(AppdomeError)"
		$ = "/efs/libloader_cache_android/"
		$ = "/ANTAMP__EFS__SPLASH__EVENTS__FAKE_JNIONLOAD"

	condition:
		any of them
		
}
