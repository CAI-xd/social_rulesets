/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: helloappworld
    Rule name: New Ruleset
    Rule id: 7057
    Created at: 2020-09-07 13:32:26
    Updated at: 2020-09-07 13:33:32
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule baiduprotect
{
    condition:
        androguard.service("com.baidu.xshield.XshieldService") or
        androguard.service("com.baidu.xshield.XshieldJobService")
}
