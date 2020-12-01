/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Khosla SDK Tracker
    Rule id: 5172
    Created at: 2018-12-29 11:22:06
    Updated at: 2018-12-29 11:22:57
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
  
rule KhoslaSDKTrackerActivity
{
        meta:
                description = "All Khosla SDK Apps"
        condition:
                androguard.activity("com.khoslalabs.aadhaarbridge.AadhaarBridge")
}
