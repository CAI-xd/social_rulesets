/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: silverfoxy
    Rule name: Fake App Campaign 1
    Rule id: 2594
    Created at: 2017-04-30 19:41:13
    Updated at: 2017-04-30 20:07:19
    
    Rating: #0
    Total detections: 64
*/

import "androguard"


rule FakeAppCampaign1
{
	meta:
		description = "This rule detects fake application with only the payment gateway delivering no service"
		sample = "c30d57bc5363456a9d3c61f8e2d44643c3007dcf35cb95e87ad36d9ef47258b4"

	strings:
		$url1 = /https:\/\/telehamkar.com\//
		$url2 = /weezweez.ir/

	condition:
		$url1 or $url2
		
}
