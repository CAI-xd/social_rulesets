/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: grvarma
    Rule name: UC_Safe
    Rule id: 2056
    Created at: 2016-12-31 08:20:14
    Updated at: 2017-01-03 11:29:51
    
    Rating: #1
    Total detections: 0
*/

import "androguard"


rule koodous : UC_Safe 
{

	condition:
		androguard.package_name("com.uc.iflow") and
		androguard.certificate.sha1("8399A145C14393A55AC4FCEEFB7AB4522A905139")  
}
