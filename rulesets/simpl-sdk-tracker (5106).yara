/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Simpl SDK Tracker
    Rule id: 5106
    Created at: 2018-12-05 09:40:09
    Updated at: 2020-03-02 12:19:53
    
    Rating: #0
    Total detections: 31
*/

import "androguard"

rule SimplSDKActivity
{
	meta:
		description = "All Simpl SDK Apps"
	strings:
		$a = "https://approvals-api.getsimpl.com/my-ip"
		$b = "https://staging-approvals-api.getsimpl.com/api/v2/"
		$c = "https://staging-subscriptions-api.getsimpl.com/api/v3/"
		$d = "https://sandbox-approvals-api.getsimpl.com/api/v2/"
		$e = "https://subscriptions-api.getsimpl.com/api/v3/"
		$f = "https://sandbox-subscriptions-api.getsimpl.com/api/v3/"
	condition:
		androguard.activity("com.simpl.android.zeroClickSdk.view.activity.BaseSimplScreen") or
		androguard.activity("com.simpl.android.sdk.view.activity.BaseSimplScreen") or
		$a or $b or $c or $d or $e or $f

}
