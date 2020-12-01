/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TimoKats
    Rule name: yara ruleset 1
    Rule id: 7233
    Created at: 2020-11-10 10:10:40
    Updated at: 2020-11-10 10:13:17
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule billiards
{
	meta:
		description = "Prevents the creation of network sockets and linking to dangerous files"  
	strings:
		$a = "android.permission.INTERNET"
        $b = "graphs.facebook.com"

	condition:
            ($a or $b)
}
