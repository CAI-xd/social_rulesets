/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: w4lls1t0
    Rule name: IberdrolaRule
    Rule id: 5304
    Created at: 2019-02-22 10:06:22
    Updated at: 2019-02-22 10:07:31
    
    Rating: #0
    Total detections: 37
*/

rule ibers {

  strings:
	$string_1 = /scottishpower\.com/
	$string_2 = /avangrid\.com/
	$string_3 = /neoenergia\.com/
	$string_4 = /iberdrola/

  condition:
	any of them
}
