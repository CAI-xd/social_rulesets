/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ke1811
    Rule name: YARA rule for apk2
    Rule id: 7368
    Created at: 2020-11-17 16:48:53
    Updated at: 2020-11-17 16:58:13
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{


	strings:
		$MD5 = "5f08fb3e2fc00391561578d0e5142ecd"
		$SHA1 = "db35baeb9fc92ea28b116ec7da02af1cd0797dcf"
		$AppName = "Viber"
		$Developer = "UMT inc."
		
		

	condition:
		$MD5 or $SHA1 or $AppName or $Developer

}
