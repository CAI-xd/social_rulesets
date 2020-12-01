/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ItsMe
    Rule name: New Ruleset
    Rule id: 7314
    Created at: 2020-11-14 10:43:18
    Updated at: 2020-11-14 20:37:02
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule SizeLimit
{

	condition:
		filesize > 3MB 
		
}
