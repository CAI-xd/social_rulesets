/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nasimevasl
    Rule name: FakeTelegram
    Rule id: 5818
    Created at: 2019-08-06 12:51:15
    Updated at: 2019-08-06 13:21:23
    
    Rating: #0
    Total detections: 26
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{


	condition:
		(androguard.service("org.telegram.messenger.AuthenticatorService") and
		androguard.service("org.telegram.messenger.NotificationsService") and not
		androguard.certificate.sha1("9723e5838612e9c7c08ca2c6573b6026d7a51f8f") )
		or
		(androguard.service("org.thunderdog.challegram.service.NetworkListenerService") and
		androguard.service("org.thunderdog.challegram.sync.StubAuthenticatorService") and not
		androguard.certificate.sha1("66462134345a6adac3c1d5aea9cef0421b7cab68") )
		
}
