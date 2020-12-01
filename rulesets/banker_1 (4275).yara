/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: GSK
    Rule name: Banker_1
    Rule id: 4275
    Created at: 2018-03-16 07:31:19
    Updated at: 2018-03-16 10:36:23
    
    Rating: #0
    Total detections: 2
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Android.Fakebank"

	condition:
		androguard.package_name("com.ibk.smsmanager") or
		androguard.package_name("com.example.kbtest")
		
		
}
