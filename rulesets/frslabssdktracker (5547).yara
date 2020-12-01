/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: FRSLabsSDKTracker
    Rule id: 5547
    Created at: 2019-05-17 12:24:03
    Updated at: 2019-05-17 12:25:05
    
    Rating: #0
    Total detections: 7
*/

import "androguard"

rule FRSLabsSDKTracker
{
	meta:
		description = "All FRSLabs SDK Apps"
	condition:
		androguard.activity("com.frslabs.android.sdk.scanid.activities.IDScannerActivity") or
		androguard.activity("com.frslabs.android.sdk.facesdk.activities.FaceCaptureActivity") or
		androguard.activity("com.frslabs.android.sdk.videosdk.ui.WorkflowActivity")
}
