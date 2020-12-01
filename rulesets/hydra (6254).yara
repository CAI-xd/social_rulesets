/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pIrasa
    Rule name: hydra
    Rule id: 6254
    Created at: 2019-12-29 01:32:31
    Updated at: 2019-12-29 01:32:42
    
    Rating: #0
    Total detections: 0
*/

rule hydra
{
        strings:
                $d2 = "utils.packed.com"
                $d1 = "core.com.packed"
        condition:
                all of them


}
