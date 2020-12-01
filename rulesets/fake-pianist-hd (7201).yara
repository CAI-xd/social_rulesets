/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: LeidenScammedMe
    Rule name: fake pianist HD
    Rule id: 7201
    Created at: 2020-11-09 15:18:42
    Updated at: 2020-11-16 15:18:09
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule apkDetect
{
	meta:
		description = "This rule detects Ransomware"
		sample = "fdd2004bbd0f6b3742330b196c386931235249af34e13141caf0afd17d39fa09"
	strings:
		$a = "http://1downloadss0ftware.xyz/gogo/go.php?name=Pianist%20HD%20:%20Piano"
	condition:
		androguard.app_name("Pianist HD Piano") and
		androguard.certificate.sha1("34b62a18d916cb599aceedc856d597b500b698bd") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.CHANGE_NETWORK_STATE/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.INTERNET/) and 
		$a
		
}
