/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Diviei
    Rule name: downloader1
    Rule id: 2127
    Created at: 2017-01-12 10:01:45
    Updated at: 2020-05-01 13:08:47
    
    Rating: #0
    Total detections: 204
*/

import "androguard"
import "file"
import "cuckoo"


rule downloader:trojan
{
	meta:
		sample = "800080b7710870e1a9af02b98ea2073827f96d3fde8ef9d0e0422f74fe7b220f"

	strings:
		$a = "Network is slow, click OK to install network acceleration tool."
		$b = "Your network is too slow"
		$c = "Awesome body. Lean and sexy."

	condition:
		all of them
}
