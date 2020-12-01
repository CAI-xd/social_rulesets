/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: colorfulsummer
    Rule name: anjian
    Rule id: 5674
    Created at: 2019-07-02 06:29:36
    Updated at: 2019-07-19 06:51:21
    
    Rating: #0
    Total detections: 702
*/

import "androguard"

rule koodous : official
{
	meta:
		description = "anjianmobile detect"


	condition:
		androguard.url("api.mobileanjian.com")		
		or androguard.url("mobileanjian.com")
		or androguard.url(/mobileanjian\.com/)
}
