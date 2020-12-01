/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: test_crypto_clipper
    Rule id: 5273
    Created at: 2019-02-13 23:52:32
    Updated at: 2019-02-14 19:01:06
    
    Rating: #0
    Total detections: 16
*/

import "androguard"
import "file"
import "cuckoo"


rule test_crypto_clipper
{
	meta:
		description = "Crypto clipper"
		md5 = "24d7783aaf34884677a601d487473f88"
		
		
	strings:
		$a_2 = "ClipboardMonitorService"
		$a_3 = "ClipboardMonitor"


	
	condition:
		all of ($a_*)
 			    
				
}
