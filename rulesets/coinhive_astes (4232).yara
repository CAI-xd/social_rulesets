/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: VaroRuiz
    Rule name: Coinhive_astes
    Rule id: 4232
    Created at: 2018-02-24 12:54:21
    Updated at: 2018-02-24 13:24:42
    
    Rating: #0
    Total detections: 0
*/

rule Coinhive
{
 strings:
   $a1 = "*rcyclmnrepv*" wide ascii
   $a2 = "*coin-hive*" wide ascii
   $a3 = "*coin-hive.com*" wide ascii
   $a4 = "*com.android.good.miner*" wide ascii

 condition:
   any of them
}
