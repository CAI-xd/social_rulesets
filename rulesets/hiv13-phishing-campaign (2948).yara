/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: silverfoxy
    Rule name: Hiv13 Phishing Campaign
    Rule id: 2948
    Created at: 2017-06-08 07:41:03
    Updated at: 2017-06-08 07:42:45
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule Hiv13PhishingCampaign
{
	meta:
		description = "This campaign shows phishing payment page and gathers users card information"
		sample = "4750fcaf255107a8ee42b6a65c3ad6c609ef55601a94f2b6697e86f31cff988c"

	strings:
		$a = /hiv13.com/

	condition:
		$a
}
