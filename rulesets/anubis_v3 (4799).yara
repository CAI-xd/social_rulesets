/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: Anubis_v3
    Rule id: 4799
    Created at: 2018-08-10 13:31:00
    Updated at: 2018-08-10 13:40:22
    
    Rating: #3
    Total detections: 415
*/

import "androguard"

rule Android_Anubis_v3
{
	meta:
		author = "Jacob Soo Lead Re"
		description = "Anubis newer version."

	condition:
		(androguard.filter(/android.intent.action.DREAMING_STOPPED/i) 
		and androguard.filter(/android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE/i) 
		and androguard.filter(/android.intent.action.USER_PRESENT/i))
}
