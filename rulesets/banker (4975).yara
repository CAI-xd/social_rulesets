/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: rupaliparate
    Rule name: banker
    Rule id: 4975
    Created at: 2018-10-11 11:24:37
    Updated at: 2019-02-26 13:56:52
    
    Rating: #0
    Total detections: 3095
*/

import "androguard"
import "file"
import "cuckoo"


rule Play
{

	strings:
		$a = "setComponentEnabledSetting"
		$b = "sendTextMessage"
		$c = "sendMultipartTextMessage"
		$d = "android.app.action.DEVICE_ADMIN_ENABLED"

	condition:
		androguard.permission(/android.permission.INTERNET/) and $a and ($b or $c) and $d and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.filter("android.app.action.DEVICE_ADMIN_DISABLED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED")
		
}
