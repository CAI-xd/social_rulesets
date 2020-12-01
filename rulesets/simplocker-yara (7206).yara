/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: s2713330
    Rule name: SimpLocker YARA
    Rule id: 7206
    Created at: 2020-11-09 18:37:41
    Updated at: 2020-11-09 19:04:50
    
    Rating: #1
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"

rule SimpLocker
{
	meta:
		description = "SimpLocker"
		sample = "fd694cf5ca1dd4967ad6e8c67241114c"
		reference = "http://kharon.gforge.inria.fr/dataset/malware_SimpLocker.html"

	strings:
		$a = "http://example.com/"
		$b = "http://xeyocsu7fu2vjhxs.onion/"
		$c = "https://check.torproject.org"

	condition:
	all of them 
		
}
