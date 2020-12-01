/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dmanzanero
    Rule name: Task_Hijacking
    Rule id: 842
    Created at: 2015-09-21 17:06:53
    Updated at: 2015-10-24 21:12:30
    
    Rating: #1
    Total detections: 5518
*/

import "androguard"



rule taskhijack : official
{
	meta:
		date = "2015-09-21"
		description = "Posible task Hijack"
		reference = "https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf"
		
	strings:
		$a = /taskAffinity\s*=/
		$b = /allowTaskReparenting\s*=/
		$file = "AndroidManifest.xml"
		
	condition:
		$file and ($a or $b)
		
}
