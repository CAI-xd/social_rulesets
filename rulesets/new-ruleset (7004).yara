/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wager47769
    Rule name: New Ruleset
    Rule id: 7004
    Created at: 2020-07-17 13:12:03
    Updated at: 2020-07-17 13:12:26
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule videogames
{
    meta:
        description = "Rule to catch APKs with package name match with videogame"
    condition:
        androguard.package_name(/videogame/)
}
