/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: rtec
    Rule name: Flashlight
    Rule id: 7352
    Created at: 2020-11-17 12:09:15
    Updated at: 2020-11-17 16:12:23
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"


rule flashlight_permissions
{
	meta:
		description = "This rule detects apk's which contain activities, found in this flashlight apk, whose permission is not in the AndroidManifest.xml file"
		original_apk = "c6060b439c7946ad6dbea754bc7961a3a32293e974e094409c3bd46496e3a8c7"

	strings:
		$a = "Landroid/content/Context;->unregisterReceiver"
		$b = "Landroid/location/LocationManager;->getLastKnownLocation"
		$c = "Landroid/media/MediaPlayer;->pause"
		$d = "Landroid/telephony/TelephonyManager;->getDeviceId"
		$e = "Landroid/net/ConnectivityManager;->registerNetworkCallback"

	condition:
		(($a and not androguard.permission(/android.permission.BROADCAST_STICKY/) )
		or
		($b and not androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) )
		or
		($b and not androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) )
		or
		($c and not androguard.permission(/android.permission.WAKE_LOCK/) )
		or
		($d and not androguard.permission(/android.permission.READ_PHONE_STATE/) )
		or
		($e and not androguard.permission(/android.permission.ACCESS_WIFI_STATE/) )
		or
		($e and not androguard.permission(/android.permission.CHANGE_NETWORK_STATE/) ))
		and
		not file.md5("c4b7256d2b1438de5cc7a1397379ec72")		
}
