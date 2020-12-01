/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: VaroRuiz
    Rule name: Pakistan 2
    Rule id: 5035
    Created at: 2018-10-31 14:48:52
    Updated at: 2018-10-31 14:49:36
    
    Rating: #0
    Total detections: 12
*/

import "androguard"
rule Pakistan

{
 strings:
  
   $a1 = "com.avanza.ambitwiz" wide ascii
   

 condition:
   $a1
   
}
