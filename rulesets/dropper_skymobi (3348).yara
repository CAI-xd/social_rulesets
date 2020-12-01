/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: zhaohouhou
    Rule name: Dropper_skymobi
    Rule id: 3348
    Created at: 2017-08-09 08:20:18
    Updated at: 2017-09-01 01:25:30
    
    Rating: #0
    Total detections: 1090
*/

import "androguard"


rule koodous : skymobi
{
	meta:
		source = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
	strings:
		$a = "Java_com_skymobi_pay_common_util_LocalDataDecrpty_Decrypt"
		$b = "Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt"
	
	condition:
		all of them
}
