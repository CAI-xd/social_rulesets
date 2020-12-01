/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: brazilianBanker_jan2020
    Rule id: 6343
    Created at: 2020-02-04 01:11:40
    Updated at: 2020-02-04 01:12:44
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"

rule brazilianBanker_jan2020
{
meta:
		description = "Detects malware listed in https://www.buguroo.com/en/blog/banking-malware-in-android-continues-to-grow.-a-look-at-the-recent-brazilian-banking-trojan-basbanke-coybot. specifically - gover.may.murder samples"
		
strings:
	$a1 = "ConexaoCentral.php"
	$a2 = "1fs34"
	$a3 = "canDrawOverlays"
	

condition:
	all of ($a*) 

}
