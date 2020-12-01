/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: TestGithub
    Rule id: 3853
    Created at: 2017-11-29 21:45:15
    Updated at: 2017-11-29 21:50:02
    
    Rating: #0
    Total detections: 536002
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "GitHub"

	strings:
		$a = "github.com"

	condition:
		$a or
		androguard.url(/github\.com/) or 
		cuckoo.network.dns_lookup(/github\.com/)
}
