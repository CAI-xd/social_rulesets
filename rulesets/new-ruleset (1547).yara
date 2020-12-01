/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: sruizcasiano
    Rule name: New Ruleset
    Rule id: 1547
    Created at: 2016-06-28 18:12:27
    Updated at: 2016-06-28 18:12:45
    
    Rating: #0
    Total detections: 4566
*/

rule AndroRat
{
        meta:
                description = "ejercicio - yarn - androrat"

        strings:
                $a = "Lmy/app/client/ProcessCommand" wide ascii
                $b = "AndroratActivity" wide ascii
                $c = "smsKeyWord" wide ascii
                $d = "numSMS" wide ascii

        condition:
                $a and ($b or $c or $d)
}
