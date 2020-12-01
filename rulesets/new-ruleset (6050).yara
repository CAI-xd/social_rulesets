/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: alemazzo
    Rule name: New Ruleset
    Rule id: 6050
    Created at: 2019-10-31 14:50:31
    Updated at: 2019-10-31 14:56:55
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule PimentoRoot : rootkit
{
	condition:
		androguard.url(/http:\/\/webserver\.onekeyrom\.com\/GetJson\.aspx/)
		
}
