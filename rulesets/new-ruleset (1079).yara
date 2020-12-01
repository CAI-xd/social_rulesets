/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: daniel_gf3
    Rule name: New Ruleset
    Rule id: 1079
    Created at: 2015-12-15 16:06:10
    Updated at: 2018-04-06 13:47:13
    
    Rating: #0
    Total detections: 87
*/

import "androguard"
import "file"
import "cuckoo"


rule Test7
{
	condition:
		androguard.package_name("com.estrongs.android.pop")
	
}
