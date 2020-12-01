/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: rijoultj
    Rule name: Flutter
    Rule id: 5149
    Created at: 2018-12-14 13:46:32
    Updated at: 2018-12-14 14:57:16
    
    Rating: #0
    Total detections: 998
*/

import "androguard"
import "file"
import "cuckoo"


rule Flutter
{
	meta:
		description = "Detect APK using flutter runtime"
		sample = "8fce0488c977c88710a9a769956543ccd900682bbb8989a23a193bfc2a8f0a92"
		
	strings:
		$a = "libflutter.so"
	
	condition:
		any of them
				
}
