/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: YBL Yes UPI SDK Tracker
    Rule id: 4652
    Created at: 2018-07-15 08:56:09
    Updated at: 2018-12-13 08:18:19
    
    Rating: #0
    Total detections: 88
*/

import "androguard"

rule PhonePeActivity
{
	meta:
		description = "All Phonepe SDK Apps"
	condition:
		androguard.activity("com.phonepe.android.sdk.ui.MerchantTransactionActivity") or
		androguard.activity("com.phonepe.android.sdk.ui.debit.views.TransactionActivity")		
}

rule YesBankActivity
{
	meta:
		description = "All YesBank UPI SDK"
	condition:
		androguard.activity("com.yesbank.TransactionStatus")
}
