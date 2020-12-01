/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: grvarma
    Rule name: Creativeglance_Safe
    Rule id: 2059
    Created at: 2017-01-03 11:38:24
    Updated at: 2017-01-03 11:40:32
    
    Rating: #1
    Total detections: 206
*/

import "androguard"


rule Safe : Creativeglance
{
	
	condition:
		androguard.certificate.sha1("2f0bd554308b8193c3486aec1d3841c70b13c866")
}
