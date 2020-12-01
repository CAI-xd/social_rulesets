/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: smspay chinnese
    Rule id: 590
    Created at: 2015-06-16 09:33:19
    Updated at: 2015-08-06 15:20:16
    
    Rating: #-1
    Total detections: 124
*/

//https://koodous.com/#/apks/395881ba248f20dfbb3b698ae32c95c436eaef776148f9e42edb768ca4e8bd7d
//
rule sms_smspay : chinnese
{
	meta:
		description = "smspay chinnese"
		thread_level = 3
		in_the_wild = true

	strings:
		$a = "res/raw/app_id.txt"
		$b_1 = "btNguyenVong3"
		$b_2 = "btNguyenVong2"
		$c_1 = "btTraDiemThi"
		$c_2 = "bjbddhjsy6"

	condition:
		$a and (any of ($b_*)) and (any of ($c_*))
}
