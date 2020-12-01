/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nikchris
    Rule name: BankBot
    Rule id: 2941
    Created at: 2017-06-07 09:47:06
    Updated at: 2017-06-07 09:49:24
    
    Rating: #0
    Total detections: 51
*/

import "androguard"
import "file"
import "cuckoo"


rule BankBot
{
	strings:
		$a = "/private/tuk_tuk.php"
		$b = "/set/tsp_tsp.php"

		
	condition:
		$a or $b
}
