/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: SystemoFramC&C
    Rule id: 3852
    Created at: 2017-11-29 16:17:15
    Updated at: 2017-11-29 16:19:42
    
    Rating: #0
    Total detections: 1
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "https://blog.zimperium.com/fake-whatsapp-real-malware-zlabs-discovered/"
		sample = "1daa6ff47d451107b843be4b31da6e5546c00a164dc5cfbf995bac24fef3bc6d "

	condition:
		androguard.url(/systemofram\.com/) or 
		cuckoo.network.dns_lookup(/systemofram\.com/)
}
