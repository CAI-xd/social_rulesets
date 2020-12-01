/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lucaegitto
    Rule name: minsdkversion
    Rule id: 626
    Created at: 2015-06-23 00:57:07
    Updated at: 2015-08-06 16:00:25
    
    Rating: #0
    Total detections: 1739687
*/

import "androguard"

rule minsdktest
{
	meta:
		description = "minsdkversion test grabber"


	strings:
		$a = /minSdkVersion/i

	condition:
		$a
		
}
