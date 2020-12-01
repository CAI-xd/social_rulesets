/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: BartMichellekVqXd
    Rule name: main.jsd
    Rule id: 7429
    Created at: 2020-11-26 09:55:19
    Updated at: 2020-11-27 09:55:51
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule mainjsd_1: mainjsd
{

	meta:
		description = "manjsd"
		sample = "7f23e272f5e946bd3bae08debe9fef0e980913d6cc0a5b6a8efcd5d756c7b750"

	strings:
		$a = "assets/main.jsd" //rule_1
		
	condition:
		$a
		
}
