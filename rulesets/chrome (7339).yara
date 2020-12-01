/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: zowoo
    Rule name: Chrome
    Rule id: 7339
    Created at: 2020-11-16 17:41:02
    Updated at: 2020-11-17 12:19:55
    
    Rating: #1
    Total detections: 0
*/

rule security: Google Chrome
{
	meta:
		info = "This rule will detect a Trojan banker"
		sha="36004af3567c2f09b108dbc30458507f38ed2e2a6f462213b5f5cd783adacc7a"
		sample_name = "Chrome"
		
		
	strings:
		$a = "tjnahlcl.tdpk.kdkl"
		$b = "iwncbde.ixkpw.jjucczi"
		$c = "ebsn.ejnaa.clswqsrq"

	condition:
		all of them
		
}
