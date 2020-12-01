/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Cyberassignment
    Rule name: SaveMe
    Rule id: 7226
    Created at: 2020-11-10 06:44:06
    Updated at: 2020-11-10 07:18:46
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "SaveMe"
		sample = "saveme_78835947CCA21BA42110A4F206A7A486"
		reference = "http://kharon.gforge.inria.fr/dataset/malware_SaveMe.html"

	strings:
		$a = "content://call_log/calls"
		$b = "http://topemarketing.com/app.html"
		$c = "android.intent.action.CALL"
		$d = "content://icc/adn"


	condition:
		all of them
		
}
