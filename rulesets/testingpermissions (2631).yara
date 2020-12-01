/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: bryTesting
    Rule name: TestingPermissions
    Rule id: 2631
    Created at: 2017-05-04 13:16:02
    Updated at: 2017-05-05 13:45:26
    
    Rating: #0
    Total detections: 8688
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "First rule used to detect certain permissions"

	condition:

		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/)
		
		
}
