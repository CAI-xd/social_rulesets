/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: Packer_Nagapt
    Rule id: 3151
    Created at: 2017-07-15 14:44:27
    Updated at: 2017-07-15 15:01:11
    
    Rating: #0
    Total detections: 14
*/

rule Nagapt
{
	meta:
		description = "Nagapt (chaosvmp)"
		
    strings:
		$nagapt_1 = "chaosvmp"
		$nagapt_2 = "ChaosvmpService"

	condition:
        any of them 
}
