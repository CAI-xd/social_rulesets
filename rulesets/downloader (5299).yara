/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: rupaliparate
    Rule name: downloader
    Rule id: 5299
    Created at: 2019-02-20 07:10:01
    Updated at: 2019-02-26 13:32:24
    
    Rating: #0
    Total detections: 1152
*/

import "androguard"
import "file"
import "cuckoo"


rule downloader : official
{

	strings:
		$a = "setComponentEnabledSetting"
		$b = "android.app.extra.DEVICE_ADMIN"
		$c = "application/vnd.android.package-archive"
		$d = "getClassLoader"

	condition:
		$a and $b and $c and $d and 
		androguard.filter("android.app.action.DEVICE_ADMIN_DISABLED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED")
		
}
