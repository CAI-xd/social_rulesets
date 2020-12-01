/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: Packer_Tencent
    Rule id: 3148
    Created at: 2017-07-15 14:43:39
    Updated at: 2017-07-15 15:01:26
    
    Rating: #0
    Total detections: 17915
*/

rule Tencent
{
	meta:
		description = "Tencent"
		
    strings:
		$tencent_1 = "TxAppEntry"
		$tencent_2 = "StubShell"
		$tencent_3 = "com.tencent.StubShell.ProxyShell"
		$tencent_4 = "com.tencent.StubShell.ShellHelper"

	condition:
        any of them 
}
