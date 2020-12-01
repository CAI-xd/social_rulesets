/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: rowland
    Rule name: airpush_rocking
    Rule id: 2330
    Created at: 2017-03-14 09:30:26
    Updated at: 2017-03-14 10:30:38
    
    Rating: #0
    Total detections: 2015
*/

rule AirPush
{
	meta:
        description = "Evidences of AirPush Adware SDK."
	strings:
		$1 = "api.airpush.com/dialogad/adclick.php"
		$2 = "Airpush Ads require Android 2.3"
   	condition:
    	1 of them
}
