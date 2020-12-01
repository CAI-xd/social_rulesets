/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: goncalosilva
    Rule name: New Ruleset
    Rule id: 3216
    Created at: 2017-07-20 11:47:41
    Updated at: 2017-07-20 21:39:16
    
    Rating: #0
    Total detections: 0
*/

import androguard
        rule adware {
            condition:
				androguard.filter("com.airpush.android.DeliveryReceiver") or
				androguard.filter(/smsreceiver/)
				androguard.filter()
        }
