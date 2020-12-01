/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: AePS MicroATM Tracker
    Rule id: 5100
    Created at: 2018-12-05 05:39:35
    Updated at: 2020-03-07 11:20:41
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule AePSMicroATM
{
	meta:
		description = "Detect All AePS apps built for MicroATM agents by a platform X"
	condition:
		androguard.url("aepsandroidapp.firebaseio.com")
}
