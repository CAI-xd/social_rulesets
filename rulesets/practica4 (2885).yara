/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: bserrano
    Rule name: Practica4
    Rule id: 2885
    Created at: 2017-05-31 17:03:59
    Updated at: 2017-05-31 18:04:59
    
    Rating: #0
    Total detections: 84
*/

rule  practica4_slempo
{
	meta:
		description=  "BANKED_SLEMPO"
	strings:
		$a= "slempo"
		$b= "intercept_sms_start"
		$c= "unblock_all_number"
	condition:
		$a and $b and $c
}
