/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: s2081318
    Rule name: SimpLocker Ruleset
    Rule id: 7251
    Created at: 2020-11-10 17:34:14
    Updated at: 2020-11-10 17:43:12
    
    Rating: #0
    Total detections: 0
*/

rule CryptoLocker: SimpLocker
{
    meta:
        description = "Ruleset that detects the SimpLocker application"
        reference = "http://kharon.gforge.inria.fr/dataset/malware_SimpLocker.html"

    strings:
        $string_1 = "TorSender" // Function title of Tor-proxying class
        $string_2 = "AesCrypt" // Function title to Encrypt files
        $string_3 = "PAYSAFECARD_DIGITS_NUMBER" // Payment method information

    condition:
        all of them
		
}
