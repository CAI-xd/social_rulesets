/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jcarneiro
    Rule name: XMR
    Rule id: 4175
    Created at: 2018-02-06 16:23:21
    Updated at: 2018-02-06 16:23:38
    
    Rating: #0
    Total detections: 582571
*/

import "androguard"
import "file"
import "cuckoo"


rule crypto : jcarneiro
{

	strings:
		$a = "xmr"

	condition:
		$a
		
}
