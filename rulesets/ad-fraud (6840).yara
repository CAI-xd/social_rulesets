/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Kvozon
    Rule name: AD Fraud
    Rule id: 6840
    Created at: 2020-04-11 09:54:05
    Updated at: 2020-04-11 10:37:00
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta: 
		description = "This rule detects AD fraud"

	condition:
		androguard.url("app/ConfServlet?conf=") or androguard.url("http://ip-api.com/json/?fields=country,countryCode")
		
}
