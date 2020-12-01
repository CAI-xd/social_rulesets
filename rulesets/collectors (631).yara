/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lucaegitto
    Rule name: Collectors
    Rule id: 631
    Created at: 2015-06-25 12:12:11
    Updated at: 2015-08-06 16:00:34
    
    Rating: #0
    Total detections: 988675
*/

import "androguard"

rule collectors
{
	meta:
		description = "Filter for private information collecting malwares"

	condition:
		androguard.permission(/android.permission.INTERNET/)
		and androguard.permission(/android.permission.READ_SMS/)
		and androguard.permission(/android.permission.READ_PHONE_STATE/)
		and androguard.permission(/android.permission.CHANGE_NETWORK_STATE/)
		and androguard.permission(/android.permission.ACCESS_WIFI_STATE/)
		and androguard.permission(/android.permission.ACCESS_NETWORK_STATE/)
		and androguard.permission(/android.permission.READ_CONTACTS/)
		and androguard.permission(/android.permission.GET_ACCOUNTS/)
		and androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/)
}
