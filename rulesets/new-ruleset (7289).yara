/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Rens
    Rule name: New Ruleset
    Rule id: 7289
    Created at: 2020-11-12 19:45:16
    Updated at: 2020-11-12 19:55:52
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		Author = "Rens en Frank"
		description = "Cajino"
		reference = "http://kharon.gforge.inria.fr/dataset/malware_Cajino.html"

	strings:
		$a = "com.baidu.android.pushservice.action.MESSAGE"
		$b = "com.baidu.android.pushservice.action.RECEIVE"
		$c = "com.baidu.android.pushservice.action.notification.CLICK"

	condition:
		all of them
		
}
