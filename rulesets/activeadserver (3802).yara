/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nremynse
    Rule name: ActiveAdServer
    Rule id: 3802
    Created at: 2017-11-02 20:16:17
    Updated at: 2017-11-02 20:16:56
    
    Rating: #0
    Total detections: 1
*/

import "androguard"
import "cuckoo"

rule AndroidAdServer
{
	meta:
		description = "Rule to catch APKs speaking to a noisy ad server"
	condition:
		androguard.url(/123\.56\.205\.151/) or
		androguard.url("123.56.205.151") or
		cuckoo.network.dns_lookup(/123\.56\.205\.151/)

}
