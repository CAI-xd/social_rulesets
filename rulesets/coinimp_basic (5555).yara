/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: axelleap
    Rule name: CoinImp_Basic
    Rule id: 5555
    Created at: 2019-05-23 10:09:51
    Updated at: 2019-05-23 10:11:23
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule coinimp_basic : official
{
	meta:
		description = "Basic rule to detect CoinImp apps - see https://www.coinimp.com/documentation"

	strings:
		$coinimp = "https://www.hostingcloud.racing/7rry.js"

	condition:
		androguard.permission(/android.permission.INTERNET/) and
		$coinimp
}
