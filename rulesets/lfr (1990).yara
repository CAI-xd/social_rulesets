/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: xo
    Rule name: LfR
    Rule id: 1990
    Created at: 2016-11-27 15:17:33
    Updated at: 2016-11-28 13:41:43
    
    Rating: #0
    Total detections: 188607
*/

import "androguard"

rule koodous : official
{
	meta:
		description = "looking for root exploit"
		sample = "16de78a5bbd91255546bfbb3565fdbe4c9898a16062c87dbb1cf24665830bbe"

	strings:
                $1 = "Get Root success"
                $2 = "libhxy"
                $3 = "libxy_arm64.so"
                $4 = "firewall"
                $5 = "busybox"
    condition:
                all of ($*)
			

}

rule construct : official
{
	meta:
		description = "looking for root exploit - constructeur"
		sample = "16de78a5bbd91255546bfbb3565fdbe4c9898a16062c87dbb1cf24665830bbe"

	strings:
                $_1 = "asus"
                $_2 = "huawei"
                $_3 = "zte"
                $_4 = "htc"
                $_5 = "sonyericsson"
    condition:
                all of ($_*)
			

}
