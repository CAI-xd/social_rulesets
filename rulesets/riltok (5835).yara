/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: joseph1731
    Rule name: Riltok
    Rule id: 5835
    Created at: 2019-08-13 16:33:05
    Updated at: 2019-08-13 16:34:02
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"

rule riltok_koo
{
    strings:
        $s1 = "librealtalk-jni.so"
        $s2 = "AmericanExpress"
        $s3 = "cziugqk"
    condition:
        all of them
}
