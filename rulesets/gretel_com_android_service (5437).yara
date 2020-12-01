/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: gretel_com_android_service
    Rule id: 5437
    Created at: 2019-04-10 00:01:09
    Updated at: 2019-04-10 21:30:54
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule gretel_com_android_service
{
	meta:
		description = "com.android.service"
		sha = "8a8a2f1c13d0d57186bc343af96abe87"
		
		
	strings:
		$a_1 = "iwtiger/plugin"
        $a_2 = "com/ryg/dynamicload/DLProxyActivity" 
        $a_3 = "com/ryg/dynamicload/DLBasePluginActivity" 
		
        	
	condition:
		all of ($a_*) and
		androguard.certificate.sha1("5E7C8FE28537307E28BEB0F82F67DF76F1A119D6")
}
