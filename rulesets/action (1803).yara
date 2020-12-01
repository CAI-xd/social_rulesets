/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: Action
    Rule id: 1803
    Created at: 2016-09-06 15:21:43
    Updated at: 2016-09-06 15:29:35
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"

rule r
{
    strings:
        $re1 = /scripts\/action_request.php$/

    condition:
        $re1
}
