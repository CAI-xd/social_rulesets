/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: chaochaoxiong
    Rule name: Banker.Anubis
    Rule id: 7092
    Created at: 2020-10-15 02:13:20
    Updated at: 2020-10-15 02:16:43
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e85cba233a555a2ecb0956c6b6fa040ad12fd9cb496fcff3d3b3a80dfe6758dc"

	strings:
		 $a1 = "U2VuZF9HT19TTVM="
       $a2 = "QUxMU0VUVElOR1NHTw=="
       $b1 = "Send_GO_SMS"
       $b2 = "del_sws"

	condition:
		all of ($a*) or all of ($b*)
		
}
