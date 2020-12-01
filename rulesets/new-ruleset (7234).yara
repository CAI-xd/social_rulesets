/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lisav
    Rule name: New Ruleset
    Rule id: 7234
    Created at: 2020-11-10 10:15:45
    Updated at: 2020-11-10 10:43:00
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Trojan : BatterySuperCharger
{
	meta:
		description = "Trojan targeting"
		sample = "269e98e6d6020cc611321c58af75fe9d8ae5ff8a"

	condition:
		androguard.package_name("com.extend.battery") and
		androguard.app_name("Battery_SuperCharger") and
		androguard.activity(/com.extend.battery.Splash/i) and
		androguard.activity(/com.extend.battery.TabHandler/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.WRITE_SMS/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.url(/http://sigma.sgadtracker.com/) and
		not file.md5("5e3fcd800f7b8db5a59554459e110f4d")
		
}
