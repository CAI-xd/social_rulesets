/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yonatangot
    Rule name: READ_EXTERNAL_STORAGE
    Rule id: 3601
    Created at: 2017-09-18 07:44:46
    Updated at: 2017-09-18 10:44:10
    
    Rating: #0
    Total detections: 889970
*/

import "androguard"
import "file"
import "cuckoo"


rule storage
{
	meta:
		description = "This rule detects READ_EXTERNAL_STORAGE"

	condition:
		androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/)
}
