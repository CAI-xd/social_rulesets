/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yonatangot
    Rule name: READ_SOCIAL_STREAM
    Rule id: 3864
    Created at: 2017-12-04 10:50:17
    Updated at: 2017-12-04 10:50:31
    
    Rating: #0
    Total detections: 10871
*/

import "androguard"
import "file"
import "cuckoo"


rule storage
{
	meta:
		description = "This rule detects READ_SOCIAL_STREAM"

	condition:
		androguard.permission(/android.permission.READ_SOCIAL_STREAM/)
}
