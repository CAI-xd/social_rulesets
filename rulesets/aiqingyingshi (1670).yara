/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: AiQingYingShi
    Rule id: 1670
    Created at: 2016-07-24 06:27:18
    Updated at: 2016-07-24 08:19:48
    
    Rating: #0
    Total detections: 53
*/

import "androguard"


rule AiQingYingShi : chinese_porn
{

	condition:
	androguard.app_name(/\xe7\x88\xb1\xe6\x83\x85[\w]+?\xe5\xbd\xb1\xe8\xa7\x86[\w]{,11}/)  //273bcec861e915f39572a169ae98d4c2afae00800259c1fe5e28c075923d90ca
		
}
