/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: davidT
    Rule name: c2dmSEND
    Rule id: 5766
    Created at: 2019-07-17 15:52:47
    Updated at: 2019-07-17 15:55:21
    
    Rating: #0
    Total detections: 116
*/

import "androguard"

rule c2dmSEND
{
	meta:
		description = "Should never be present in any apps - https://firebase.google.com/docs/reference/android/com/google/firebase/iid/FirebaseInstanceIdReceiver"

	condition:
		androguard.permission(/com\.google\.android\.c2dm\.permission\.SEND/)
}
