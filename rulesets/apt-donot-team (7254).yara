/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: chased
    Rule name: apt donot team
    Rule id: 7254
    Created at: 2020-11-11 08:23:19
    Updated at: 2020-11-11 08:46:32
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "donot team "
		sample = "7eb237a9f97801d9eb0bed65103ffc89"

	strings:
		$a = "test"

	condition:
		androguard.package_name("com.tencent.mobileqq") and
		androguard.app_name("System Service") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.certificate.sha1("61ed377e85d386a8dfee6b864bd85b0bfaa5af81") and
		androguard.permission(/android.permission.READ_SMS/) and
		file.size<1000000 and
		not $a
		
		
}
