/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: doopel23
    Rule name: WhatsupTrojan
    Rule id: 5565
    Created at: 2019-05-29 09:35:28
    Updated at: 2019-05-29 10:21:26
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "droidbox"

rule WhatsupTrojan
{
	meta:
		description = "This rule detects the WhatsupTrojan app based on different indicators"
		family = "WhatsupTrojan"


	condition:
		  (
			  androguard.permission(/REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and
			  androguard.permission(/REQUEST_DELETE_PACKAGES/) and
			  androguard.permission(/SYSTEM_ALERT_WINDOW/) and
			  androguard.permission(/ACCESS_NETWORK_STATE/) and
			  androguard.permission(/WAKE_LOCK/) and
			  androguard.permission(/INTERNET/)
		  )
		  and
		  (
		  	  androguard.activity(/\.Asterisk$Act/) and
			  androguard.activity(/\.Consulate$RequestActivity/) and
			  androguard.activity(/\.CaptureData$AlertActivity/) and
			  androguard.activity(/\.CaptureData$WebViewActivity/) or
			  androguard.activity(/\.SUActivity/) or
			  androguard.activity(/\.ScreenOnAndUnlock/)
		  )
		  and
		  (
		  	  androguard.service(/AccService/i) and
			  androguard.service(/GeneralService/i) and
			  androguard.service(/RegisterReceiverService/i) and
			  androguard.service(/Operation/i)
									
		  )
}
