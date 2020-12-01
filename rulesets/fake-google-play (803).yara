/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ldelosieres
    Rule name: Fake Google Play
    Rule id: 803
    Created at: 2015-08-29 17:55:49
    Updated at: 2015-08-29 18:08:36
    
    Rating: #1
    Total detections: 13956
*/

import "androguard"

rule FakeGooglePlay
{
	meta:
		description = "Fake Google Play applications"

	condition:
		androguard.app_name(/google play/i) and
		not androguard.certificate.sha1("38918A453D07199354F8B19AF05EC6562CED5788")
}
