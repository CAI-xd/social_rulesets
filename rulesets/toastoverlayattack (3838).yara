/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Disane
    Rule name: ToastOverlayAttack
    Rule id: 3838
    Created at: 2017-11-22 13:23:31
    Updated at: 2017-11-22 13:33:29
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"


rule koodous : official
{
	meta:
		description = "Looks up Toast Overlayer Attacking Apps"

	strings:
		$a = "device_policy"
		$b = "clipboard"
		$c = "power"
		$d = "com.android.packageinstaller"
		$e = "bgAutoInstall"

	condition:
		$a and
		$b and
		$c and 
		$d and 
		$e and
		androguard.activity(/MyAccessibilityServiceTmp/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/)
}
