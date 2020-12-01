/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: Packers
    Rule id: 1584
    Created at: 2016-07-07 11:05:45
    Updated at: 2016-07-07 15:36:09
    
    Rating: #0
    Total detections: 237
*/

rule packers 
{
	meta:
		description = "This rule detects packers based on files used by them"
		

	strings:
		$bangcle_1 = "libsecmain.so"
		$bangcle_2 = "libsecexe.so"
		$i360_1 = "libjiagu.so"
		$i360_2 = "libjiagu_art.so"
		$ali_1 = "libmobisecy.so"
		$ali_2 = "libmobisecy1.zip"
		$baidu_1 = "libbaiduprotect.so"
		$baidu_2 = "baiduprotect.jar"
		$baidu_3= "libbaiduprotect_x86.so"
		$tencent_1 = "libmain.so"
		$tencent_2 = "libshell.so"
		$qihoo_1 = "monster.dex"
    	$qihoo_2 = "/libprotectClass"
		$liapp_1 = "LIAPPEgg.dex"
    	$liapp_2 = "/LIAPPEgg"
		$apkprotect_1 = ".apk@"
    	$apkprotect_1 = "/libAPKProtect"

	condition:
		2 of them
		
}
