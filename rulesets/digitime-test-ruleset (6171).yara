/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Ninji
    Rule name: Digitime Test ruleset
    Rule id: 6171
    Created at: 2019-12-02 17:50:57
    Updated at: 2019-12-02 18:21:22
    
    Rating: #0
    Total detections: 2
*/

import "androguard"
import "file"
import "cuckoo"


rule digitimeTest
{
	meta:
		description = "Test to detect Digitime malware"
		
	strings:
		$key1 = "Ti92T_77Zij_MiTik"
		$key2 = "HiBox_5i5j_XiMik"
		$key3 = "Ti92R_37Rak_AiTia"
		$key4 = "HsTi67_AuIs39_Ka23"
		$key5 = "HsTi67_Ka23"
		$fnv = "FindNewViewsion"
		$dtInfo = "com.dtinfo.tools"

	condition:
		(androguard.receiver(/Rvc$/) and androguard.service(/Svc$/)) or (any of ($key*)) or $fnv or $dtInfo
		
}
