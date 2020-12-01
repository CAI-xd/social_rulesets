/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: berni
    Rule name: Slempo detection rule
    Rule id: 2825
    Created at: 2017-05-29 22:05:57
    Updated at: 2017-05-29 22:07:41
    
    Rating: #0
    Total detections: 223
*/

import "androguard"
import "file"
import "cuckoo"


rule slempoBMG
 
{
    meta:
        description = "Regla yara para detectar malware de la familia slempo"
 
    strings:
        $a = "slempo"
        $b = "content://sms/inbox"
        $c = "DEVICE_ADMIN"
 
    condition:
        $a and ($b or $c)
}
