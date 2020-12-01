/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: grvarma
    Rule name: PUA_Ozzie
    Rule id: 2063
    Created at: 2017-01-03 11:58:19
    Updated at: 2017-01-10 09:12:24
    
    Rating: #1
    Total detections: 12
*/

import "androguard"
import "file"
import "cuckoo"


rule PUA : Ozzie
{


	condition:
		androguard.certificate.sha1("c24d1b4c81226bad788c0d266bba520ec0d8c2f7") 
		
}
