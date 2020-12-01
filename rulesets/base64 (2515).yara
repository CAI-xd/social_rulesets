/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: SadFud
    Rule name: base64
    Rule id: 2515
    Created at: 2017-04-20 23:59:29
    Updated at: 2017-04-21 00:02:32
    
    Rating: #0
    Total detections: 432412
*/

rule bas64
{
  strings:
      $b64 = "base64_decode"
  condition:
      $b64    
}
