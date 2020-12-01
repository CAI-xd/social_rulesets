/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pIrasa
    Rule name: allatori_demo
    Rule id: 6250
    Created at: 2019-12-27 11:21:00
    Updated at: 2020-01-01 16:50:31
    
    Rating: #0
    Total detections: 55
*/

rule allatori_demo
{
  meta:
    description = "Allatori demo"
    url         = "http://www.allatori.com/features.html"
    author      = "Ahmet Bilal Can"
    sample      = "7f2f5aac9833f7bdccc0b9865f5cc2a9c94ee795a285ef2fa6ff83a34c91827f"
    sample2     = "8c9e6c7b8c516499dd2065cb435ef68089feb3d4053faf2cfcb2b759b051383c"
  
  strings:
  /*
      while (i >= 0) {
          int i2 = i - 1;
          cArr[i] = (char) (str.charAt(i) ^ 'T');
          if (i2 < 0) {
              break;
          }
          i = i2 - 1;
          cArr[i2] = (char) (str.charAt(i2) ^ '9');
      }
  */

  $twokeyxor = {
      3a 00 1? 00         //   if-ltz v0, :cond_0
      6e 20 ?? ?? ?4 00   //   invoke-virtual {p0, v0}, Ljava/lang/String;->charAt(I)C
      0a 0?               //   move-result v2
      d8 0? 0? ff         //   add-int/lit8 v3, v0, -0x1
      df 0? 0? ??         //   xor-int/lit8 v2, v2, 0x54
      8e ??               //   int-to-char v2, v2
      50 0? 0? 0?         //   aput-char v2, v1, v0
      3a 0? 0? 00         //   if-ltz v3, :cond_0
      d8 00 0? ff         //   add-int/lit8 v0, v3, -0x1
      6e 20 ?? ?? 34 00   //   invoke-virtual {p0, v3}, Ljava/lang/String;->charAt(I)C
      0a 0?               //   move-result v2
      df 0? 0? ??         //   xor-int/lit8 v2, v2, 0x39
      8e ??               //   int-to-char v2, v2
      50 0? 0? 0?         //   aput-char v2, v1, v3
  }

  condition:
      $twokeyxor

}
