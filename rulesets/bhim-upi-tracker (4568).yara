/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: BHIM UPI Tracker
    Rule id: 4568
    Created at: 2018-06-22 09:42:30
    Updated at: 2018-12-13 08:12:31
    
    Rating: #0
    Total detections: 274
*/

import "androguard"

rule UPIPINActivity
{
	meta:
		description = "All UPI PIN Activity apps"	
	condition:
		androguard.activity("org.npci.upi.security.pinactivitycomponent.GetCredential")				
}

rule BHIMAadhaarUPITrackerActivity
{
	meta:
		description = "All TCS AePS UPI apps"	

	condition:
		androguard.activity("com.tcs.merchant.cags.UPIPaymentFragment")		
}
