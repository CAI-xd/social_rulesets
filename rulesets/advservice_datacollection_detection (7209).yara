/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jko3333
    Rule name: advservice_datacollection_detection
    Rule id: 7209
    Created at: 2020-11-09 19:36:55
    Updated at: 2020-11-09 20:18:25
    
    Rating: #0
    Total detections: 0
*/

rule advservice_datacollection_detection
{
	meta:
		description =  "entifies this specific BadNews apk by the AdvService creation and information gathering by the use of variables."
		in_the_wild = True
	strings:
		$advservicelog_event = "AdvService started"
		$datavesn = "vesn"
		$datapacnme = "pacNme"
		$dataphMl = "phMl"
	condition:
		$advservicelog_event and $datavesn and $datapacnme and $dataphMl
}
