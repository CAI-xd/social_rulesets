/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Ludovic
    Rule name: Target_Bank_Paypal
    Rule id: 2651
    Created at: 2017-05-05 14:21:13
    Updated at: 2017-05-05 14:22:09
    
    Rating: #0
    Total detections: 37130
*/

import "androguard"
import "file"
import "cuckoo"


rule Target_Bank_Paypal : official
{
	strings:
		$string_target_bank_paypal = "com.paypal.android.p2pmobile"
	condition:

	($string_target_bank_paypal)
}
