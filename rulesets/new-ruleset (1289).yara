/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pgrtechdeveloper
    Rule name: New Ruleset
    Rule id: 1289
    Created at: 2016-03-14 13:16:55
    Updated at: 2016-03-14 13:17:59
    
    Rating: #0
    Total detections: 0
*/

rule prueba
{

meta: description = "Prueba"

strings:
$a = "giving me your money"
condition: $a
}
