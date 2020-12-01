/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Henk249
    Rule name: superguitarsolo
    Rule id: 7412
    Created at: 2020-11-18 13:03:28
    Updated at: 2020-11-18 13:04:42
    
    Rating: #0
    Total detections: 0
*/

rule guitarsupersolo {
        meta:
            desc = "YARA Rule to detect suspicious activity"
        strings:
            $a = "rooter"
            $b = "0x992c35d3"
        condition:
            $a and $b
    }
