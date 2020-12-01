/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: POB_1
    Rule id: 4523
    Created at: 2018-06-12 19:04:51
    Updated at: 2018-06-12 19:06:59
    
    Rating: #0
    Total detections: 4110
*/

import "androguard"

rule POB_1
{
	meta:
		description = "Detects few POB apps"
		
	condition:
		(androguard.receiver(/android\.app\.admin\.DeviceAdminReceiver/) and
		 androguard.service(/pob\.xyz\.WS/))
		
}
