/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: Packer_Apkprotect
    Rule id: 3155
    Created at: 2017-07-15 14:46:34
    Updated at: 2017-07-15 15:00:52
    
    Rating: #0
    Total detections: 83
*/

rule Apkprotect
{
	meta:
		description = "Apkprotect"
		
    strings:
		$apkprotect_1 = ".apk@"
    	$apkprotect_2 = "libAPKProtect"
		$apkprotect_3 = "APKMainAPP"

	condition:
         ($apkprotect_1 and $apkprotect_2) or $apkprotect_3
}
