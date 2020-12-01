/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: GhostFramework+EventDex
    Rule id: 3774
    Created at: 2017-10-30 07:49:12
    Updated at: 2017-10-30 07:52:11
    
    Rating: #0
    Total detections: 82
*/

import "androguard"
import "file"
import "cuckoo"

/*
http://www.freebuf.com/articles/terminal/150360.html
*/
rule GhostFrameWork_EventDex
{
	strings:
		$a = "EventDex"

	condition:
		$a		
}
