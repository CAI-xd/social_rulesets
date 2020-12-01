/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jcarneiro
    Rule name: Mobby
    Rule id: 3589
    Created at: 2017-09-14 15:28:52
    Updated at: 2017-10-31 11:21:43
    
    Rating: #0
    Total detections: 792
*/

import "androguard"
import "file"
import "cuckoo"


rule mobby
{

	strings:
		$a = "io/mobby/sdk/receiver"
		$b = "io/mobby/sdk/activity"
		$c = "mobby"

	condition:
		any of them
		
}
