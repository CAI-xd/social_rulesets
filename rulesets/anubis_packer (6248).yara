/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pIrasa
    Rule name: anubis_packer
    Rule id: 6248
    Created at: 2019-12-27 10:11:53
    Updated at: 2019-12-28 23:25:48
    
    Rating: #0
    Total detections: 28
*/

rule Anubis
{
        strings:
                //$addplusandff = { d8 0? 0? 0? d5 ?? ff 00 48 0? 0? 0? b0 ?? d5 ?? ff 00        }
                //$agetagetaddand = { 48 0? 0? 0? 48 0? 0? 0? b0 ?? d5 ?? ff 00 }
                //$aget = { 48 0? 0? 0? 48 0? 0? 0?}
                
                $swap = { 48 0? 03 0? 48 0? 03 0? 4f 0? 03 0? 4f 0? 03 0? 0f 0? }
        condition:
                #swap == 1
}
