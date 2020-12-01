/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: s2081318
    Rule name: SmsBoxer / Love-Box Ruleset
    Rule id: 7250
    Created at: 2020-11-10 17:09:39
    Updated at: 2020-11-10 17:34:06
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule Trojan : SmsBoxer
{
    meta:
        description = "Trojan abusing pay-per-SMS services"
        source = "26c69c790a8d651f797c36e6183b5d56b02bf211d58ad3f69888f40029154bed"

    strings:
        $string_1 = "http://androgamer.ru/engine/download.php?id=363" nocase
        $string_2 = "2438+1305299+x+a" nocase
		
    condition:
        all of ($string_*)
        and (
            androguard.permission(/android.permission.RECEIVE_SMS/) 
            or androguard.permission(/android.permission.READ_SMS/)
        )
}
