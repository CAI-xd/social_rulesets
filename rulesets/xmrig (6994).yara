/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kokosnoob
    Rule name: xmrig
    Rule id: 6994
    Created at: 2020-07-06 15:04:15
    Updated at: 2020-07-06 15:04:30
    
    Rating: #0
    Total detections: 0
*/

import "cuckoo"


rule xmrigStrings
{
    strings:
        $fee = "fee.xmrig.com" wide ascii
        $nicehash = "nicehash.com" wide ascii
        $minergate = "minergate.com" wide ascii
        $stratum = "stratum+tcp://" wide ascii


    condition:
       $fee and
       $nicehash and
       $minergate and
       $stratum 
}
