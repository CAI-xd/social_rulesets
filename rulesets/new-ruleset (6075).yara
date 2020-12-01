/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nekmo
    Rule name: New Ruleset
    Rule id: 6075
    Created at: 2019-11-01 20:43:51
    Updated at: 2019-11-01 20:50:34
    
    Rating: #0
    Total detections: 0
*/

import "file"
import "androguard"

rule rosy_strings_plus_manifest
{
        meta:
        	description = "description"
		author = "me"

        strings:
            $s4 = "string4"
            $s3 = "string3"

        condition:
            ($s3 or $s4) and 
            ( 
                androguard.receiver("receiver") and
                androguard.filter("filter")
            )
}
