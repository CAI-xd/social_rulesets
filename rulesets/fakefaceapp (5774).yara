/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: fakeFaceApp
    Rule id: 5774
    Created at: 2019-07-19 21:11:34
    Updated at: 2019-07-19 22:12:34
    
    Rating: #0
    Total detections: 15
*/

import "androguard"
import "file"
import "cuckoo"


rule fakeFaceAPp
{
        meta:
                description="Detects fake FaceApp malware/adware"

        strings:
                $a1 = "id=ru.sotnik.metallCalck"
                $a2 = "myLogs"

        condition:
                all of ($a*)
}
