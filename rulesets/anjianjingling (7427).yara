/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: BartMichellekVqXd
    Rule name: anjianjingling
    Rule id: 7427
    Created at: 2020-11-26 09:06:41
    Updated at: 2020-11-27 09:57:20
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule anjian_1: jinling
{

	meta:
		description = "anjianjianling"
		sample = "ce84bbd4359a621084f405635c4eb7853b7af8647e819a6d4b4b40db81511e92"

	strings:
		$a = "assets/script.lc" //rule_1
		$b = "mobileanjian.com" 
		
	condition:
		$a or $b
		
}
