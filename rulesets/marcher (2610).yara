/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dmaciejak
    Rule name: Marcher
    Rule id: 2610
    Created at: 2017-05-03 03:31:41
    Updated at: 2017-05-19 07:35:14
    
    Rating: #0
    Total detections: 155
*/

import "androguard"

rule Marcher : AlarmAction
{
	meta:
		description = "This rule detects marcher new versions"
		sample = "c20318ac7331110e13206cdea2e7e2d1a7f3b250004c256b49a83cc1aa02d233"
		author = "DMA"

	condition:
		androguard.filter(/p\d{3}\w\.AlarmAction/)
}
