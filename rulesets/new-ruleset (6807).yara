/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jhouweling
    Rule name: New Ruleset
    Rule id: 6807
    Created at: 2020-03-28 17:53:28
    Updated at: 2020-03-29 10:38:01
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"

rule Rule_EliteVPN
{
meta:
description = "This rule detects the EliteVPN application, as analyzed in exercise A"

condition:
file.sha256("3350990c4d298cdb4dc94ba886a27147e501bbf8fd504d824be53cad5cb02142") and
androguard.activity("sri.gznpahefisyqjrqahrpozs.ygsbxqfxnjrszmwy.vuqnglz") and
androguard.permission(/BROADCAST_WAP_PUSH/) and
androguard.permissions_number > 10 and
androguard.url("https://facebook.com/device?user_code=%1$s&qr=1")
}
