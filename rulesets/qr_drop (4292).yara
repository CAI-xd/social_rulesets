/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: QR_drop
    Rule id: 4292
    Created at: 2018-03-27 00:57:18
    Updated at: 2018-03-27 00:57:22
    
    Rating: #0
    Total detections: 3
*/

import "androguard"
import "file"
import "cuckoo"


rule QR_drop
{
	meta:
		description = "This rule detects malicious samples hiding behind QR apps"
		blog = "https://nakedsecurity.sophos.com/2018/03/23/crooks-infiltrate-google-play-with-malware-lurking-in-qr-reading-utilities/"
		sample = "66c770c15c9a3c380a7fdd51950a3797"

	condition:
		androguard.service(/android.support.graphics.base.BaseService/) and
		androguard.receiver(/android.support.graphics.broadcast.RestartServiceBroadCast/)
		
}
