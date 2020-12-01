/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Ninji
    Rule name: Digitime Services Backdoor
    Rule id: 6173
    Created at: 2019-12-02 20:11:04
    Updated at: 2019-12-02 20:13:54
    
    Rating: #0
    Total detections: 1
*/

import "androguard"
import "file"
import "cuckoo"


rule digitimeBackdoor
{
	meta:
		description = "detects the Digitime backdoor"

	strings:
		$intf = "android.app.ILightsService"
		$internel = "com.android.internel.slf4j"
		$uid1 = "uisTeOpCk"
		$uid2 = "iWoPZrScPM1IeF"
		$sv1 = "orgslfaM"
		$sv2 = "orgslfyP"
		$sv3 = "orgslfpb"
		$svName = "fo_sl_enhance"

	condition:
		any of them
		
}
