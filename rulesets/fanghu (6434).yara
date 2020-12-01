/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: thatqier
    Rule name: fanghu
    Rule id: 6434
    Created at: 2020-03-02 09:21:17
    Updated at: 2020-03-02 09:24:26
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule fanghu : official
{
	condition:
		androguard.app_name("fanghu")
		
}
