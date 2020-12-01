/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: VaroRuiz
    Rule name: Coinminer service
    Rule id: 4234
    Created at: 2018-02-24 14:12:15
    Updated at: 2018-10-31 09:55:49
    
    Rating: #0
    Total detections: 16
*/

rule Coinhive4
{
 strings:
   $a1 = "CoinHiveIntentService" wide ascii
   $a2 = "com.kaching.kingforaday.service.CoinHiveIntentService" wide ascii

   
 condition:
   any of them
}
