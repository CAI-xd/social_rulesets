/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: 2019_anubis_downloader
    Rule id: 5252
    Created at: 2019-02-05 00:59:15
    Updated at: 2019-02-05 01:02:50
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule anubis_downloader
{
	meta:
		description = "Anubis downloader"
		sha256 = "bc87c9fffcdac4eea1b84c62842ce1138fd90ed6"
		
		
	strings:
		$a_1 = "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
		$a_2 = "urlAdminPanel"
		$a_3 = "kill"
		$a_4 = "idbot"
		$a_5 = "CheckCommand"

	
	condition:
		all of ($a_*)
 			    
				
}
