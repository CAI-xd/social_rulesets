/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: Packer_Ijiami
    Rule id: 3149
    Created at: 2017-07-15 14:44:01
    Updated at: 2017-07-15 15:01:21
    
    Rating: #0
    Total detections: 6165
*/

rule Ijiami
{
	meta:
		description = "Ijiami"
		
    strings:
		$1jiami_1 = "assets/ijiami.dat"
		$1jiami_2 = "ijiami.ajm"
		$1jiami_3 = "assets/ijm_lib/"
		$1jiami_4 = "libexecmain.so"
		$1jiami_5 = "libexec.so"
		$1jiami_6 = "rmeabi/libexecmain.so"
		$1jiami_7 = "neo.proxy.DistributeReceiver"

	condition:
        any of them 
}
