/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mk
    Rule name: Mire tools
    Rule id: 7391
    Created at: 2020-11-18 04:33:24
    Updated at: 2020-11-18 04:47:17
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule Mire
{
	meta:
		description = "Mire tools"
		sample = "adc8178e9bcabfdf931583768f3596f2dc3237c8bed0af4c6a869fa43040a78a"

	strings:
		$a = "chenxuan"
		$b = "tbs"

	condition:
		$a and
		$b and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and 
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/)
		
}
