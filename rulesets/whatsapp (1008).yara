/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: WhatsAPP
    Rule id: 1008
    Created at: 2015-11-10 12:39:47
    Updated at: 2015-11-11 07:30:17
    
    Rating: #0
    Total detections: 1251
*/

import "androguard"
import "file"

rule testing
{
	meta:
		description = "WhatsAPP stealer?"
		
	strings:
	  $b1 = "8d4b155cc9ff81e5cbf6fa7819366a3ec621a656416cd793"
	  $b2 = "1e39f369e90db33aa73b442bbbb6b0b9"
	  $b3 = "346a23652a46392b4d73257c67317e352e3372482177652c"
	condition:
		any of them

		
}
