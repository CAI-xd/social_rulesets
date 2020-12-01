/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: rajca
    Rule name: New Ruleset
    Rule id: 5396
    Created at: 2019-04-01 15:10:32
    Updated at: 2019-04-02 07:37:02
    
    Rating: #0
    Total detections: 90
*/

import "androguard"

rule sdks
{
	condition:
		androguard.app_name(/bank/)
}
