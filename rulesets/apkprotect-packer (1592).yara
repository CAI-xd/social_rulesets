/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: ApkProtect packer
    Rule id: 1592
    Created at: 2016-07-07 15:39:56
    Updated at: 2016-08-24 13:14:37
    
    Rating: #0
    Total detections: 1829
*/

rule packers : apkprotect
{
	meta:
		description = "This rule detects packers based on files used by them"
		

	strings:
		$apkprotect_1 = ".apk@"
    	$apkprotect_2 = "libAPKProtect"

	condition:
		2 of them
		
}
