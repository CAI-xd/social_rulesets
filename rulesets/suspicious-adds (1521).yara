/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: Suspicious Adds
    Rule id: 1521
    Created at: 2016-06-16 19:45:14
    Updated at: 2016-06-16 20:01:55
    
    Rating: #0
    Total detections: 33613
*/

import "androguard"
import "file"
import "cuckoo"


rule SuspiciousAdds
{
	meta:
		description = "This rule looks for suspicios activity"

	condition:
		androguard.activity(/com.startapp.android.publish.OverlayActivity/i) or androguard.activity(/com.greystripe.sdk.GSFullscreenActivity/i)
		
}
