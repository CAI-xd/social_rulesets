/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: MaximeIngrao
    Rule name: Covid19 - AdFraud
    Rule id: 6823
    Created at: 2020-04-01 17:27:09
    Updated at: 2020-04-01 17:45:34
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Covid:AdFraud
{
	meta:
		description = "This rule detects the Covid19 application with AdFraud suspicious signatures"

	condition:
		(androguard.package_name(/corona/i) or
		androguard.package_name(/covid/i) or
		androguard.app_name(/corona/i) or
		androguard.app_name(/covid/i)) and		
		((androguard.permission(/android.permission.INTERNET/) and (androguard.permission(/android.permission.ACCESS_WIFI_STATE/) or androguard.permission(/CHANGE_WIFI_STATE/))) or
		(androguard.permission(/android.permission.INTERNET/) and androguard.permission(/android.permission.BIND_NOTIFICATION_LISTENER_SERVICE/)))
}
