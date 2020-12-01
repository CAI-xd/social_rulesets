/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: throwsomeaway
    Rule name: New Ruleset
    Rule id: 7406
    Created at: 2020-11-18 12:16:02
    Updated at: 2020-11-18 12:41:45
    
    Rating: #0
    Total detections: 0
*/

rule Similar_radio_apps : radio
{
	meta:
		description = "Detection of interesting radio apps"
		threat_level = 0
		sample = "aba15a6abbe812ec23018abed9738c85"

	strings:
		$a = "android.permission.ACCESS_COARSE_LOCATION"
		$b = "android.permission.ACCESS_FINE_LOCATION"
		$c = "android.permission.ACCESS_NETWORK_STATE"
		$d = "android.permission.BROADCAST_STICKY"
		$e = "android.permission.GET_TASKS"
		$f = "android.permission.READ_PHONE_STATE"
		$g = "android.permission.WAKE_LOCK"
		$h = "android.permission.RECORD_AUDIO"
		$i = "android.permission.WRITE_EXTERNAL_STORAGE"
		$j = "android.permission.INTERNET"
		$k = "radio"
	condition:
		($a or $b or $c or $d or $e or $f or $g) and $h and $i and $j and $k
		

}
