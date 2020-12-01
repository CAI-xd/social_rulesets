/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jcarneiro
    Rule name: CryptoThreats
    Rule id: 4174
    Created at: 2018-02-06 16:15:19
    Updated at: 2018-02-06 16:18:09
    
    Rating: #0
    Total detections: 41
*/

import "androguard"
import "file"
import "cuckoo"


rule crypto : jcarneiro
{

	strings:
		$a = "pool.minexmr.com"

	condition:
		$a
		
}
