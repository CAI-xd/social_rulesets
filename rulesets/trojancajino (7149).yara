/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kaka
    Rule name: TrojanCajino
    Rule id: 7149
    Created at: 2020-11-06 12:07:31
    Updated at: 2020-11-06 12:10:49
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule TrojanCajino
{
    meta:
   description = "Trojan which uses the Chinese search engine Baidu"


    strings:
        $a = "com.baidu.android.pushservice.action.MESSAGE"
        $b = "com.baidu.android.pushservice.action.RECEIVE" 
        $c = "com.baidu.android.pushservice.action.notification.CLICK"
        
      
    condition:
        $a and $b and $c
}
