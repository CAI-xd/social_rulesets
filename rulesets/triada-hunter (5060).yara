/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: doopel23
    Rule name: Triada Hunter
    Rule id: 5060
    Created at: 2018-11-16 09:07:35
    Updated at: 2018-11-16 09:12:52
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
  
rule Android_Triada : android
{
  meta:
    author = "Doopel"
    description = "This rule try to detects Android.Triada.Malware"
    sample = "4656aa68ad30a5cf9bcd2b63f21fba7cfa0b70533840e771bd7d6680ef44794b"

  strings:
    $string_1 = "android/system/PopReceiver"
    $string_2 = "VF*D^W@#FGF"
    $string_3 ="export LD_LIBRARY_PATH"
  condition:
      any of ($string_*) and
      androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and
      androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
      androguard.permission(/android.permission.GET_TASKS/) and
		  androguard.activity("org.cocos2dx.cpp.VideoPlayer") and 
			androguard.activity("com.cy.smspay.HJActivity") and 
	    androguard.activity("com.b.ht.FJA") and 
	    androguard.activity("com.door.pay.sdk.DnPayActivity") and 
	    androguard.activity("com.alipay.android.app.sdk.WapPayActivity") and 
	    androguard.activity("com.cy.pay.TiantianSMPay")
 }
