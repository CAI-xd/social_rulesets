/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: orenk
    Rule name: droidpluginClass
    Rule id: 2197
    Created at: 2017-01-30 11:21:34
    Updated at: 2017-01-30 11:22:53
    
    Rating: #0
    Total detections: 18013
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{

	strings:
		$droidplugin = "droidplugin"
	condition:
		$droidplugin
		
}
