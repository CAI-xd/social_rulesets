/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: madalina
    Rule name: New Ruleset
    Rule id: 589
    Created at: 2015-06-16 08:36:10
    Updated at: 2015-06-23 08:52:52
    
    Rating: #0
    Total detections: 1019
*/

rule dropper:realshell {
	meta:
		source = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
	strings:
		$a = "hexKey:"
		$b = "Decrypt.malloc.memset.free.pluginSMS_encrypt.Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt.strcpy"
	
	condition:
		any of them
}
