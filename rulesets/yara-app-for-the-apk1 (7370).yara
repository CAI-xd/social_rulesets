/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ke1811
    Rule name: YARA app for the apk1
    Rule id: 7370
    Created at: 2020-11-17 17:10:30
    Updated at: 2020-11-17 17:10:30
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{


	strings:
		$MD5 = "8037c51ababaaeb8da4d8a0b460223a2"
		$SHA1 = "b657d2817ff6d511d6c2b725c58180721d1e153c"
		$AppName = "Hediye Kutusu"
		$Developer = "Hediye Fun Corp."
		
		 

	condition:
		$MD5 or $SHA1 or $AppName or $Developer

}
