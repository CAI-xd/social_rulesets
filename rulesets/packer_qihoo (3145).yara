/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: Packer_Qihoo
    Rule id: 3145
    Created at: 2017-07-15 14:42:01
    Updated at: 2017-07-17 18:31:54
    
    Rating: #0
    Total detections: 1489
*/

rule Packer_Qihoo
{
	meta:
		description = "Qihoo 360"
		
    strings:
		$qihoo_1 = "libprotectClass.so"
		$qihoo_2 = "monster.dex"
		$qihoo_3 = "libqupc"
		$qihoo_4 = "com.qihoo.util.StubApplication"
		$qihoo_5 = "com.qihoo.util.DefenceReport"
		$qihoo_6 = "libprotectClass"

	condition:
        any of them 
}
