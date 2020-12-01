/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: rijoultj
    Rule name: Xamarin DexProtector
    Rule id: 5152
    Created at: 2018-12-15 08:22:43
    Updated at: 2018-12-15 08:23:44
    
    Rating: #0
    Total detections: 80
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
		$a = "environmentChecksXamarin"
		$b = "doProbe"
		$c = "positiveRootCheck"
	
	condition:
		any of them
				
}
