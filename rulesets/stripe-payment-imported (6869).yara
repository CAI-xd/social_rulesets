/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: JulienThomas
    Rule name: Stripe payment imported
    Rule id: 6869
    Created at: 2020-04-26 20:53:08
    Updated at: 2020-04-26 20:54:28
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects stripe related apps"  
 
	condition: 
        androguard.activity("com.stripe.android.view.PaymentMethodsActivity") 
}
