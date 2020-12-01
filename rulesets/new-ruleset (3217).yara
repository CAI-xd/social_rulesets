/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: CSTE
    Rule name: New Ruleset
    Rule id: 3217
    Created at: 2017-07-20 11:54:38
    Updated at: 2017-07-21 05:53:29
    
    Rating: #0
    Total detections: 6
*/

import "androguard"


rule pokemon
{
	condition:

		androguard.app_name(/pokemongo/i)
		
}
