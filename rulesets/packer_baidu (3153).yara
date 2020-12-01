/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: Packer_Baidu
    Rule id: 3153
    Created at: 2017-07-15 14:46:09
    Updated at: 2017-07-15 15:00:59
    
    Rating: #0
    Total detections: 2543
*/

rule Baidu
{
	meta:
		description = "Baidu"
		
    strings:
		$baidu_1 = "libbaiduprotect.so"
		$baidu_2 = "baiduprotect1.jar"
		$baidu_3 = "baiduprotect.jar"
		$baidu_4= "libbaiduprotect_x86.so"
		$baidu_5 = "com.baidu.protect.StubApplication"
		$baidu_6 = "com.baidu.protect.StubProvider"
		$baidu_7 = "com.baidu.protect.A"
		$baidu_8 = "libbaiduprotect"

	condition:
        any of them 
}
