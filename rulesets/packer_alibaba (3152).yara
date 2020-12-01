/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: Packer_Alibaba
    Rule id: 3152
    Created at: 2017-07-15 14:44:39
    Updated at: 2017-07-15 15:01:05
    
    Rating: #0
    Total detections: 18041
*/

rule Alibaba
{
	meta:
		description = "Alibaba"
		
    strings:
		$ali_1 = "libmobisec.so"
		$ali_2 = "libmobisecy1.zip"
		$ali_3 = "mobisecenhance"
		$ali_4 = "StubApplication"

	condition:
        any of them 
}
