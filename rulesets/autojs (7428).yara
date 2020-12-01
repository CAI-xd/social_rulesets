/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: BartMichellekVqXd
    Rule name: autojs
    Rule id: 7428
    Created at: 2020-11-26 09:43:56
    Updated at: 2020-11-27 09:55:57
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule autojs_1: autojs
{

	meta:
		description = "aujojs"
		sample = "ca39abfbca6f508329434186cf38d35e37bf5c0999eb39d1ad08f21a6b059ca9"

	strings:
		$a = "assets/project/main.js" //rule_1
		$b = "assets/project/project.json"
		
	condition:
		$a or $b
		
}
