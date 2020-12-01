/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: MasterPass QR Activity Tracker
    Rule id: 5174
    Created at: 2019-01-01 16:04:14
    Updated at: 2019-01-01 16:05:07
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule MasterPassQRActivityTracker
{
	meta:
		description = "All Masterpass QR Scan Apps"
	condition:
		androguard.activity("com.masterpassqrscan.MasterPassQrCodeCaptureActivity")
}
