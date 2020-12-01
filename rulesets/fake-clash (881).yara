/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: Fake Clash
    Rule id: 881
    Created at: 2015-10-02 15:46:46
    Updated at: 2017-10-13 14:30:34
    
    Rating: #0
    Total detections: 5244
*/

import "androguard"

rule FakeClashOfClans
{
	meta:
		description = "Fake Clash of clans applications"

	condition:
		androguard.app_name(/clash of clans/i) and
		not androguard.certificate.sha1("456120D30CDA8720255B60D0324C7D154307F525")
}
