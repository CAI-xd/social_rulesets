/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: deletescape
    Rule name: Oxygen OS Unauth Reboot
    Rule id: 5991
    Created at: 2019-10-24 12:19:32
    Updated at: 2019-10-24 12:27:07
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule oneplus : UnauthReboot
{
	meta:
		description = "On Oxygen OS 9 this App allows other apps to reboot the device without any user interaction"
		source = "https://twitter.com/deletescape/status/1186644224986566660"

	condition:
		androguard.package_name("cn.oneplus.nvbackup") and
		androguard.activity(/NvSyncRebootActivity/i)
		
}
