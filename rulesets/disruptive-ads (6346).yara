/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: miriki19
    Rule name: Disruptive Ads
    Rule id: 6346
    Created at: 2020-02-04 18:43:55
    Updated at: 2020-02-05 22:10:05
    
    Rating: #0
    Total detections: 10417
*/

rule DisruptiveAds
{
	meta:
		description = "This rule detects apps that use distruptive ads"

	strings:
        $susp_string1 = "onBackPressed"
        $susp_string2 = "doubleBackToExitPressedOnce"

	condition:
      $susp_string1 or $susp_string2

}
