/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: zhaohouhou
    Rule name: SmsTrojan
    Rule id: 3832
    Created at: 2017-11-20 03:45:55
    Updated at: 2017-11-28 08:15:03
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule smstrojan : smstrojan
{
	meta:
		description = "Android album-like malware, contains malicious apk."
		sample = "8d67c9640b831912a124f3506dc5fba77f18c4e58c8b0dad972706864f6de09c"

	strings:
		$a = "send Message to"
		$b = "Tro instanll Ok"
		$c = "ois.Android.xinxi.apk"

	condition:
		all of them
		
}
