/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: Packer_i360
    Rule id: 3146
    Created at: 2017-07-15 14:43:10
    Updated at: 2017-07-17 18:32:13
    
    Rating: #0
    Total detections: 50069
*/

rule Packer_i360
{
	meta:
		description = "i360"
		
    strings:
		$i360_1 = "libjiagu.so"
		$i360_2 = "libjiagu_art.so"

	condition:
        any of them 
}
