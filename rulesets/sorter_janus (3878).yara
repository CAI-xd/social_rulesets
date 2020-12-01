/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: sorter_janus
    Rule id: 3878
    Created at: 2017-12-07 11:49:13
    Updated at: 2017-12-22 01:20:29
    
    Rating: #0
    Total detections: 1687872
*/

import "androguard"
import "file"
import "cuckoo"


/*
6465780A30333500
*/
rule sorter_janus
{
	strings:
		$a = {64 65 78 0A 30}

	condition: 
		$a		
}
