/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Bob212121
    Rule name: test_rule
    Rule id: 7322
    Created at: 2020-11-15 19:10:58
    Updated at: 2020-11-16 14:26:17
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule videogames
{

    condition:
		androguard.permission("android.permission.INTERNET")
}
