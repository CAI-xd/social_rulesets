/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Sarcares
    Rule name: Testing Androguard API Rule
    Rule id: 3056
    Created at: 2017-06-27 17:42:38
    Updated at: 2017-06-27 20:26:43
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"

rule APITesting : NotNecessaryMalware
{
	meta:
		description = "This rule was created just to test extensively the androguard API"
		disclaimer = "does not match necessary any kind of malware, it was created randomly"

	condition:
		file.size > 512KB
		and androguard.number_of_permissions >= 20
		and androguard.number_of_filters <= 100
		and androguard.number_of_activities > 30
		and (
			androguard.number_of_providers > 1
			or androguard.number_of_services > 1
		)
}
