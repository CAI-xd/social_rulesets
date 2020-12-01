/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: arrzuaw1
    Rule name: bicho
    Rule id: 2807
    Created at: 2017-05-29 10:54:59
    Updated at: 2017-09-22 19:49:27
    
    Rating: #0
    Total detections: 1905
*/

import "androguard"

rule bicho {

	strings:
		$string_1 = /CREATE TABLE IF NOT EXISTS raw_events/
		$string_2 = /com\.google\.firebase\.provider\.FirebaseInitProvider/
	condition:
		1 of ($string_*) and
		androguard.permission(/android.permission.READ_SMS/) and 
		androguard.permission(/android.permission.CAMERA/) and 
		androguard.permission(/com.google.android.c2dm.permission.RECEIVE/) and 
		androguard.permission(/android.permission.INTERNET/) and 
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/)
		
}
