/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: throwaway
    Rule name: New Ruleset
    Rule id: 7379
    Created at: 2020-11-17 20:50:07
    Updated at: 2020-11-17 20:51:16
    
    Rating: #1
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"

rule sushinow
{
    strings:
        $launcher_image = "EA DB A8 44 25 9A 27 93 8A 25 D2 E0 A2 42 8B D6 F8 10 11 F2 C4 5D 10 D2 8B FA D5 8C DC 5E 85 FA F5 E3 90 9F 23 1B DB BE 45 AC B2 86 0D 19 33 CB 5F 1F A9 0A 45 A3 40 E4 AC 3C 58 58 7D A6 F7 DB B9 00 20 A4 8D 82 B3 60 3A EA 4E 32 43 DB B7 8A A9 3E 8E 58 58 22 05 88 6C 9F 2F 7A 24 91 CC B1 2A 40 CE 82 19 F1 6B 2B 3F 18 66 B4 4E 4E 74 FB 56 31 49 24 73 B6 CF 17 3D 91 42 14 31 40 E3 8B C8 4F AD 3C 0F 15 B3 27 C6 B1 AD 49 5D BF 87 9C 9C E8 F6 AD 64 AA AF E3 06 10 59 70 BF E0 74 48 64 9E 95 01 E2 9C F9 F1 6B CB 55 D8 ED EF BA 93 2C E1 ED 5B C9 1C 12 99 B7 E0 7E C1 19 09 44 11 01 74 CB 95 DC 95 48 26 63 D4 F0 F6 AD 06 91 EA"
        $app_id = "013df7ae-6c39-4a9e-9151-fd626d536dcc"
        $app_server = "EhUbWAcbLRoGAD5FHQAJ"

    condition:
        $launcher_image or $app_id or $app_server
}
