/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: Igexin
    Rule id: 738
    Created at: 2015-07-24 08:07:42
    Updated at: 2015-08-06 16:00:39
    
    Rating: #2
    Total detections: 114028
*/

import "androguard"
import "file"
import "cuckoo"


rule Igexin
{
	meta:
		description = "igexin"
		thread_level = 3
		in_the_wild = true

	strings:

		$strings_a = "android.intent.action.GTDOWNLOAD_WAKEUP"

	

	condition:
		any of ($strings_*)
}
