/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Luisa369
    Rule name: Malicious apk - qq
    Rule id: 7183
    Created at: 2020-11-09 10:58:20
    Updated at: 2020-11-09 22:09:30
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule qq : malicious apk
{
	meta:
		description = "This rule detects the apk qq[NOT DETECTED] and similar apks"
		sample = "b09efef6d7ebd0f793fc7584cfa73181b54c3861fa7c00e7e172b889cd50102d"
		
	strings:
        $interesting_string = "xmlpull.org/v1/doc/features.html#indent-output" nocase
		
		$http_request = "data.flurry.com/aap.do"
		
		$calls_highlighted_1 = "android.location.LocationManager.getLastKnownLocation" nocase
		$calls_highlighted_2 = "android.telephony.TelephonyManager.getNetworkOperator" nocase
		$calls_highlighted_3 = "android.telephony.TelephonyManager.getNetworkOperatorName" nocase
		$calls_highlighted_4 = "android.util.Base64.decode" nocase
		$calls_highlighted_5 = "android.util.Base64.encode" nocase
		$calls_highlighted_6 = "javax.crypto.Cipher.doFinal" nocase
		
		$cryptographical_algorithms_observed = "AES" nocase
		$cryptographical_keys_observed = "UYGy723!Po-efjve"
		$encoding_algorithms_observed = "base64" nocase
		$decoded_text = "com.tencent.igx" nocase
		
		$highlighted_text_1 = "Enter password" nocase
		$highlighted_text_2 = "password-input" nocase
		$highlighted_text_3 = "Cancel" nocase
		$highlighted_text_4 = "OK" nocase

	condition:
		androguard.package_name("com.hughu") or
		androguard.app_name("qq[NOT DETECTED]") or
		androguard.certificate.sha1("967fad7b875343b14a84d3c240210941074e6cb7") or 
		(
			androguard.activity("com.applisto.appremium.classes.PasswordActivity") and
			androguard.activity("com.koushikdutta.superuser.RequestActivity") and
			androguard.permission(/android.permission.INTERNET/) and
			androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
			(
				$interesting_string or
				$http_request or
				any of ($calls_highlighted_*) or
				$cryptographical_algorithms_observed or
				$cryptographical_keys_observed or
				$encoding_algorithms_observed or
				$decoded_text or
				all of ($highlighted_text_*)
			)
		)			
}
