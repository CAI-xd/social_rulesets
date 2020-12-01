/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pIrasa
    Rule name: seC*
    Rule id: 5237
    Created at: 2019-01-30 11:58:56
    Updated at: 2019-03-23 06:57:57
    
    Rating: #0
    Total detections: 176
*/

import "androguard"

rule sec : v1
{

	condition:
		androguard.package_name(/seC./) 
		
}
