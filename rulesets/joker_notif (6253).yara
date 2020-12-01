/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pIrasa
    Rule name: joker_notif
    Rule id: 6253
    Created at: 2019-12-28 23:20:53
    Updated at: 2020-01-13 12:08:49
    
    Rating: #0
    Total detections: 0
*/

rule joker_notif 
{
    strings:
        $notif_op = 
        { 
        6e 10 ?? ?? 0a 00 
        0c 00 
        6e 10 ?? ?? 00 00 
        0c 00 
        6e 10 ?? ?? 0a 00 
        0c 01 
        54 11 ?? 00 
        6e 10 ?? ?? 0a 00 
        0c 02 
        62 03 ?? ?? 
        71 10 ?? ?? 03 00 
        0c 03 
        12 44 
        23 44 ?? ?? 
        1c 05 ?? ?? 
        12 06 
        4d 05 04 06 
        1c 05 ?? ?? 
        12 17 
        4d 05 04 07 
        1c 05 ?? ?? 12 28 4d 05 04 08 12 35 1c 09 ?? ?? 4d 09 04 05 71 54 ?? ?? 10 32 0c 00 62 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 62 02 ?? ?? 23 73 ?? ?? 1c 04 ?? ?? 4d 04 03 06 6e 30 ?? ?? 21 03 0c 01 23 72 ?? ?? 62 03 ?? ?? 4d 03 02 06 6e 30 ?? ?? 01 02 0c 00 1f 00 ?? ?? ?? ?? ?? ?? 23 82 ?? ?? 1c 03 ?? ?? 4d 03 02 06 1c 03 ?? ?? 4d 03 02 07 6e 30 ?? ?? 10 02 0c 00 12 01 23 82 ?? ?? 4d 0b 02 06 4d 0a 02 07 6e 30 ?? ?? 10 02 
        }
    condition:
        $notif_op

}
