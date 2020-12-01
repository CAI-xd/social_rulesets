/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: deedoz
    Rule name: Fishy_DevAdmin
    Rule id: 5868
    Created at: 2019-08-23 08:27:24
    Updated at: 2019-08-23 08:59:02
    
    Rating: #0
    Total detections: 563
*/

import "androguard"

rule DeviceAdmin
{
    meta:
        description = "Checks for Device Admin filters, enables the app to control the device"

    condition:
	androguard.filter(/ACTION_DEVICE_ADMIN/) or
	androguard.permission(/BIND_DEVICE_ADMIN/)
}
