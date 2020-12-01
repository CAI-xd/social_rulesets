/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pIrasa
    Rule name: allatori_com
    Rule id: 6249
    Created at: 2019-12-27 11:20:01
    Updated at: 2019-12-27 11:20:35
    
    Rating: #0
    Total detections: 2
*/

rule allatori_commercial
{
    strings:
    /*
        while (i >= 0) {
            int i4 = i3 - 1;
            cArr[i3] = (char) ((str.charAt(i3) ^ stringBuffer.charAt(i2)) ^ 11);
            if (i4 < 0) {
                break;
            }
            i3 = i4 - 1;
            int i5 = i2 - 1;
            cArr[i4] = (char) ((str.charAt(i4) ^ stringBuffer.charAt(i2)) ^ 'N');
            if (i5 < 0) {
                i5 = length;
            }
            i2 = i5;
            i = i3;
        }
        return new String(cArr);
    */

    $stacktracexor = {
        0a 00               //   move-result v0
        23 05 ?? ??         //   new-array v5, v0, [C
        d8 00 00 ff         //   add-int/lit8 v0, v0, -0x1
        01 13               //   move v3, v1
        01 02               //   move v2, v0
        3b 00 08 00         //   if-gez v0, :cond_1
        22 00 ?? ??         //   new-instance v0, Ljava/lang/String;
        70 20 ?? ?? 50 00   //   invoke-direct {v0, v5}, Ljava/lang/String;-><init>([C)V
        11 00               //   return-object v0
        d8 06 02 ff         //   add-int/lit8 v6, v2, -0x1
        6e 20 ?? ?? 28 00   //   invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C
        0a 00               //   move-result v0
        6e 20 ?? ?? 34 00   //   invoke-virtual {v4, v3}, Ljava/lang/String;->charAt(I)C
        0a 07               //   move-result v7
        b7 70               //   xor-int/2addr v0, v7
        df 00 00 ??         //   xor-int/lit8 v0, v0, 0x35
        8e 00               //   int-to-char v0, v0
        50 00 05 02         //   aput-char v0, v5, v2
        3a 06 ea ff         //   if-ltz v6,
        6e 20 ?? ?? 68 00   //   invoke-virtual {p0, v6}, Ljava/lang/String;->charAt(I)C
        0a 00               //   move-result v0
        6e 20 ?? ?? 34 00   //   invoke-virtual {v4, v3}, Ljava/lang/String;->charAt(I)C
        0a 02               //   move-result v2
        b7 20               //   xor-int/2addr v0, v2
        df 00 00 ??         //   xor-int/lit8 v0, v0, 0x6
        8e 07               //   int-to-char v7, v0
        d8 02 06 ff         //   add-int/lit8 v2, v6, -0x1
        d8 00 03 ff         //   add-int/lit8 v0, v3, -0x1
        50 07 05 06         //   aput-char v7, v5, v6
        3b 00 03 00         //   if-gez v0,
        01 10               //   move v0, v1
    }

    condition:
        $stacktracexor

}
