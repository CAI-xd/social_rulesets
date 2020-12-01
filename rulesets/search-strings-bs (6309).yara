/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kaneda
    Rule name: Search strings BS
    Rule id: 6309
    Created at: 2020-01-16 06:52:53
    Updated at: 2020-01-16 08:19:55
    
    Rating: #0
    Total detections: 120
*/

rule String_search
{

        strings:
                $c2_1 = /sabadell\.com/ nocase
                $c2_2 = /tsb\.uk\.co/ nocase
                $c2_3 = /mx\.bancosabadel/ nocase
                $c2_4 = /bancosabadell/ nocase
                $c2_5 = /bancsabadell/ nocase
                $c2_6 = /activobank/ nocase
                $c2_7 = /uk\.co\.tsb/ nocase
                $c2_8 = /bancosabadell\.mx/ nocase
                $c2_9 = /sabadell/ nocase

        condition:
                1 of ($c2_*)

}
