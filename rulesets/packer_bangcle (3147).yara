/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: Packer_Bangcle
    Rule id: 3147
    Created at: 2017-07-15 14:43:24
    Updated at: 2017-07-17 18:31:30
    
    Rating: #0
    Total detections: 2832
*/

rule Packer_Bangcle
{
	meta:
		description = "Bangcle (SecApk)"
		
    strings:
		$bangcle_1 = "libsecmain.so"
		$bangcle_2 = "libsecexe.so"
		$bangcle_3 = "bangcleplugin"	
		$bangcle_4 = "libsecexe.x86"
		$bangcle_5 = "libsecmain.x86"
		$bangcle_6 = "SecApk"
		$bangcle_7 = "bangcle_classes"	
		$bangcle_8 = "assets/bangcleplugin"
		$bangcle_9 = "neo.proxy.DistributeReceiver"

		$bangcle_10 = "libapkprotect2.so"
		$bangcle_11 = "assets/bangcleplugin/container.dex"
		$bangcle_12 = "bangcleclasses.jar"
		$bangcle_13 = "bangcle_classes.jar"
		
	condition:
        any of them 
}
