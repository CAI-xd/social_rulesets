/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Mi3_Security_Machine_Learning
    Rule name: Add_device_admin_activity
    Rule id: 2944
    Created at: 2017-06-07 17:29:41
    Updated at: 2017-06-07 17:34:30
    
    Rating: #0
    Total detections: 54185
*/

import "androguard"


rule add_device_admin_activity : official
{
	meta:
		description = "This rule detects apps that request add device admin activity"
	

	strings:
		$a = "android.app.action.ADD_DEVICE_ADMIN"

	condition:
		androguard.activity(/ACTION_ADD_DEVICE_ADMIN/i) or
		$a 
		
}
