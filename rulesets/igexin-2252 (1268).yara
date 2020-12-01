/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: Igexin 2.2.5.2
    Rule id: 1268
    Created at: 2016-03-13 20:08:34
    Updated at: 2016-03-13 20:09:58
    
    Rating: #0
    Total detections: 7909
*/

import "androguard"
import "file"
import "cuckoo"


rule Igexin2252
{
	meta:
		description = "igexin2.2.2."
		thread_level = 3
		in_the_wild = true

	strings:

		$strings_a = "com.igexin.sdk.PushReceiver"
		$strings_b = "2.2.5.2"

	

	condition:
		any of ($strings_*)
}
