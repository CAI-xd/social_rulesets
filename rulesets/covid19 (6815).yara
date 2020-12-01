/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fsociety
    Rule name: Covid19
    Rule id: 6815
    Created at: 2020-04-01 08:20:58
    Updated at: 2020-04-02 07:43:29
    
    Rating: #0
    Total detections: 3
*/

import "androguard"
import "file"
import "cuckoo"


rule corona_pkg : covid19
{
	condition:
		androguard.package_name(/corona/i)
		
}

rule covid_pkg : covid19
{
	condition:
		androguard.package_name(/covid/i)
		
}

rule corona_app_name : covid19
{
	condition:
		androguard.app_name(/corona/i)
		
}

rule covid_app_name : covid19
{
	condition:
		androguard.app_name(/covid/i)
		
}
