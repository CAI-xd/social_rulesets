/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pIrasa
    Rule name: callerApp
    Rule id: 6105
    Created at: 2019-11-16 14:55:57
    Updated at: 2019-11-16 15:02:25
    
    Rating: #0
    Total detections: 27
*/

import "androguard"
import "file"
import "cuckoo"


rule callerapp : first
{


	condition:
		(
		androguard.package_name(/monster/) or 
		androguard.package_name(/truck/) or 
		androguard.package_name(/car/) or
		androguard.package_name(/game/)) and
		androguard.permission(/ACCESS_NETWORK_STATE/) and
		androguard.permission(/CALL_PHONE/) and
		androguard.permission(/CAMERA/) and
		androguard.permission(/INTERNET/) and
		androguard.permission(/READ_PHONE_STATE/) and
		androguard.permission(/RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/VIBRATE/) and
		androguard.permission(/WAKE_LOCK/)
		
}
