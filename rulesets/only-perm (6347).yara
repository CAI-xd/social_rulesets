/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: miriki19
    Rule name: Only Perm
    Rule id: 6347
    Created at: 2020-02-04 19:29:14
    Updated at: 2020-02-05 22:01:26
    
    Rating: #0
    Total detections: 2181
*/

import "androguard"

rule SuspPerm
{
   condition:
	 androguard.permission(/(SEND|WRITE)_SMS/)
}
