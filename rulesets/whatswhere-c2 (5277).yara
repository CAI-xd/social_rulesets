/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: secauvr2
    Rule name: whatswhere c2
    Rule id: 5277
    Created at: 2019-02-14 16:53:53
    Updated at: 2019-02-14 17:10:53
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "whatwhere c2"

	strings:
		$a = "load.php?hwid="

	condition:
		$a
}
