/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: rupaliparate
    Rule name: fakebank
    Rule id: 5354
    Created at: 2019-03-12 12:32:41
    Updated at: 2019-03-12 12:46:45
    
    Rating: #0
    Total detections: 1
*/

import "androguard"
import "file"
import "cuckoo"


rule icici
{
	meta:
		description = "Rule to find fakebank"
		
	condition:
		not androguard.package_name(/com.csam.icici.bank.imobile/) and
		androguard.app_name("icici") and not androguard.certificate.issuer(/O=ICICI BANK/)		
}

rule hdfc
{
	meta:
		description = "Rule to find fakebank"
		
	condition:
		not androguard.package_name(/com.snapwork.hdfcbank/) and
		androguard.app_name("hdfc") and not androguard.certificate.issuer(/O=Snapwork/)			
}

rule axis
{
	meta:
		description = "Rule to find fakebank"
		
	condition:
		not androguard.package_name(/com.axis.mobile/) and
		androguard.app_name("axis") and not androguard.certificate.issuer(/O=AXIS BANK/)			
}
