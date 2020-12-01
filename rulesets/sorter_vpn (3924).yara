/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: sorter_vpn
    Rule id: 3924
    Created at: 2017-12-27 06:54:51
    Updated at: 2017-12-27 06:55:36
    
    Rating: #0
    Total detections: 4540
*/

import "androguard"
import "file"
import "cuckoo"

rule vpn
{
	
	strings:
		$a = "android.permission.BIND_VPN_SERVICE"

	condition:
		$a 
}
