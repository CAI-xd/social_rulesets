/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: HypervergeSDKTracker
    Rule id: 6303
    Created at: 2020-01-15 05:39:01
    Updated at: 2020-01-15 05:47:45
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule HypervergeSDKTracker
{
	meta:
		description = "All Hyperverge SDK Apps"
	condition:
		androguard.activity("co.hyperverge.hypersnapsdk.activities.HVFaceActivity") or
		androguard.activity("co.hyperverge.hvinstructionmodule.activities.FaceInstructionActivity")
}
