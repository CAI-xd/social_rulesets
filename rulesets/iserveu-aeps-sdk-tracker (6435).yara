/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: iServeU AePS SDK Tracker
    Rule id: 6435
    Created at: 2020-03-03 10:02:05
    Updated at: 2020-03-03 10:04:40
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule iServeUSDKActivity
{
	meta:
		description = "All iServeU AePS SDK Apps"
	condition:
		androguard.activity("com.iserveu.aeps.aepslibrary.dashboard.DashboardActivity") or
		androguard.activity("com.iserveu.aeps.aepslibrary.microatm.MicroAtmActivity") or
		androguard.activity("com.iserveu.aeps.aepslibrary.WelcomeMATMSdkActivity") or
		androguard.activity("com.iserveu.aeps.aepslibrary.transaction.ReportActivity") or
		androguard.activity("com.iserveu.aeps.aepslibrary.transactionstatus.TransactionStatusActivity") or
		androguard.activity("com.iserveu.aeps.aepslibrary.transaction.TransactionReceiptActivity")
}
