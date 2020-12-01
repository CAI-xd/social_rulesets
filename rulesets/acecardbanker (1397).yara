/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: AcecardBanker
    Rule id: 1397
    Created at: 2016-05-17 10:04:32
    Updated at: 2016-05-17 10:12:52
    
    Rating: #1
    Total detections: 5
*/

import "androguard"
import "file"
import "cuckoo"


rule Banker
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "26d704d3a84a1186ef9c94ccc6d9fbaf, efe11f32c6b02370c7a98565cadde668"

	strings:
		$a = "http://xxxmobiletubez.com/video.php"
		$b = "http://adultix.ru/index.php"
		$c = "http://adultix.ru/forms/index.php"
	condition:
		all of them

}
