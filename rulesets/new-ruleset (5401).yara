/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: rajca
    Rule name: New Ruleset
    Rule id: 5401
    Created at: 2019-04-02 08:58:02
    Updated at: 2019-04-02 09:23:21
    
    Rating: #0
    Total detections: 1
*/

import "androguard"


rule koodous : official
{
	condition:
		androguard.service("com.shunwang.service.CoreService")		
}
