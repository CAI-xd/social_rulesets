/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: sorter_jar
    Rule id: 3570
    Created at: 2017-09-12 08:18:00
    Updated at: 2017-09-12 08:22:14
    
    Rating: #0
    Total detections: 678
*/

import "androguard"
import "file"
import "cuckoo"
import "droidbox"


rule sorter : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"

	condition:
		droidbox.written.filename(/EOZTzhVG.jar/) or
		droidbox.written.filename(/libus.so/)
}
