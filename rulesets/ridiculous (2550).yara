/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pham
    Rule name: Ridiculous
    Rule id: 2550
    Created at: 2017-04-24 08:56:01
    Updated at: 2017-05-02 14:15:58
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"
import "droidbox"


rule koodous : official
{
	meta:
		description = "Ridiculous"
		sample = "https://koodous.com/apks?search=package_name:com.bnzve.qdcja https://koodous.com/apks?search=package_name:com.rebofjxojp.kpvhswsnwc"

	//strings:
		//$a = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}

	condition:
		droidbox.written.data("<string name=\"url\">http")
 
		
		
		
}
