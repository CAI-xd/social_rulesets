/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: davidT
    Rule name: lakeview
    Rule id: 5022
    Created at: 2018-10-30 04:38:27
    Updated at: 2020-04-20 02:32:26
    
    Rating: #0
    Total detections: 29
*/

import "androguard"

rule lionmobi
{
	meta:
		description = "lionmobi sketchy cleaner artifact"
		sample = "25f69a80ca602e9b2e81ed1c22ab62d91706bc13144ef490550aecbd7a73383a"

	condition:
		androguard.activity(/com\.example\.lakes/)
		}
