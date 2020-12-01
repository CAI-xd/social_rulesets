/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ldelosieres
    Rule name: SMSSender
    Rule id: 900
    Created at: 2015-10-08 20:37:38
    Updated at: 2015-10-17 17:09:41
    
    Rating: #0
    Total detections: 218046
*/

import "droidbox"

rule SMSSender
{
	meta:
		description = "SMS Sender"
		
	condition:
		droidbox.sendsms(/./)
		and not droidbox.sendsms("122")
}
