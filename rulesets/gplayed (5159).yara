/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: doopel23
    Rule name: GPlayed
    Rule id: 5159
    Created at: 2018-12-21 08:35:08
    Updated at: 2018-12-21 09:23:44
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "droidbox"


rule GPlayed
{
	meta:
		description = "This rule detects the GPlayed torjan malware"
		sample = "a342a16082ea53d101f556b50532651cd3e3fdc7d9e0be3aa136680ad9c6a69f"

	strings:
		$a = "assets/g/images/amex.png"
		$a2 = /"Hello" : "Hello World, Click Me!"/
		$a3 = /"ApplicationName" : "eClient"/

	condition:
		any of ($a*) 
		and(
		  androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		  androguard.permission(/android.permission.WRITE_CONTACTS/) and
		  androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		  androguard.permission(/android.permission.UNINSTALL_SHORTCUT/) and
		  androguard.permission(/android.permission.INTERNET/) and
		  androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		  androguard.permission(/android.permission.WAKE_LOCK/) and
		  androguard.permission(/android.permission.SEND_SMS/) and
		  androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and
		  androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		  androguard.permission(/android.permission.BIND_DEVICE_ADMIN/) and
		  androguard.permission(/android.permission.GET_TASKS/) and
		  androguard.permission(/android.permission.CALL_PHONE/) and
		  androguard.permission(/android.permission.CHANGE_NETWORK_STATE/) and
		  androguard.permission(/android.permission.PACKAGE_USAGE_STATS/) and
		  androguard.permission(/android.permission.READ_PHONE_STATE/) and
		  androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
		  androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		  androguard.permission(/android.permission.READ_SMS/) and
		  androguard.permission(/android.permission.READ_CONTACTS/) and
		  androguard.permission(/android.permission.RECEIVE_SMS/)
		)
		and (
			droidbox.read.filename(/shared_prefs\/conf.xml/i)
		)
		and(
		    androguard.target_sdk >= 22 and
			androguard.min_sdk >= 10 and
			androguard.service(/eService/i) and
			androguard.receiver(/eBoot/i) and 
			androguard.receiver(/Receive/i) and
			androguard.receiver(/SMSSentReceiver/i) and
			androguard.receiver(/eAdminReceiver/i)
		)
}
