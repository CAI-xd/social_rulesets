/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: omeh2003
    Rule name: Chrysaor
    Rule id: 5645
    Created at: 2019-06-24 21:43:01
    Updated at: 2019-06-24 21:44:37
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Samsung : Chrysaor 
{

	condition:
		androguard.package_name("com.network.android") and		
		file.sha256("ade8bef0ac29fa363fc9afd958af0074478aef650adeb0318517b48bd996d5d5") 
		
		
		
}
