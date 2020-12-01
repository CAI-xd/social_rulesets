/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: chased
    Rule name: anyouid
    Rule id: 6931
    Created at: 2020-05-20 11:12:41
    Updated at: 2020-05-21 03:28:33
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		
	strings:
		$a = "DataSync" nocase
		$b = "SlideShow" nocase
      $c = "IMEI Number"  nocase
      $d = "ImageView" nocase
		

	condition:
		
		3 of them
		
		
		
}
