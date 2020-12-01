/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: AppSuit Stealien obfuscator
    Rule id: 4684
    Created at: 2018-07-23 17:21:39
    Updated at: 2018-11-26 20:18:07
    
    Rating: #0
    Total detections: 82
*/

import "androguard"
import "file"
import "cuckoo"


rule stealien : protector
{
  meta:
    description = "AppSuit"


    strings:
        $a = "stealien" nocase

    condition:
        all of them
}
