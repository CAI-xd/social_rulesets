/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Custom packer Test 71 apkguard?
    Rule id: 4611
    Created at: 2018-07-02 16:27:41
    Updated at: 2018-11-29 10:05:13
    
    Rating: #0
    Total detections: 11
*/

import "androguard"
import "file"
import "cuckoo"


rule unk_packer_a : packer
{

  meta:
    description = "Unknown packer"
    url         = "https://github.com/rednaga/APKiD/issues/71"
    example     = "673b3ab2e06f830e7ece1e3106a6a8c5f4bacd31393998fa73f6096b89f2df47"
 


  strings:
    $str_0 = { 11 61 74 74 61 63 68 42 61 73 65 43 6F 6E 74 65 78 74 00 } // "attachBaseContext"
    $str_1 = { 04 2F 6C 69 62 00 } // "/lib"
    $str_2 = { 17 4C 6A 61 76 61 2F 6C 61 6E 67 2F 43 6C 61 73 73 4C 6F 61 64 65 72 3B 00 } // Ljava/lang/ClassLoader;
    $str_3 = { 77 72 69 74 65 64 44 65 78 46 69 6C 65 00 } // writedDexFile

    /**
      public void attachBaseContext(Context base) {
          super.attachBaseContext(base);
          try {
              getClass().getDeclaredMethod(GaoAoxCoJpRm("MS4zNiguNyIBJCQ9HAU="), new Class[0]).invoke(this, new Object[0]);
          } catch (Exception e) {
          }
      }
    */
    $attachBaseContextOpcodes = {
        // method.public.Lpykqdxlnyt_iytDlJSoOg.Lpykqdxlnyt_iytDlJSoOg.method.attachBaseContext_Landroid_content_Context__V:
        6f20??00??00   // invoke-super {v3, v4}, Landroid/app/Application.attachBaseContext(Landroid/content/Context;)V
        6e10??00??00   // invoke-virtual {v3}, Ljava/lang/Object.getClass()Ljava/lang/Class;
        0c??           // move-result-object v0
        1a01??00       // const-string v1, str.MS4zNiguNyIBJCQ9HAU ; 0xdfd
        6e20??00??00   // invoke-virtual {v3, v1}, Lpykqdxlnyt/iytDlJSoOg.GaoAoxCoJpRm(Ljava/lang/String;)Ljava/lang/String;
        0c??           // move-result-object v1
        12??           // const/4 v2, 0               ; Protect.java:79
        2322??00       // new-array v2, v2, [Ljava/lang/Class; ; 0x3b8
        6e30??00????   // invoke-virtual {v0, v1, v2}, Ljava/lang/Class.getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
        0c??           // move-result-object v0
        12??           // const/4 v1, 0
        2311??00       // new-array v1, v1, [Ljava/lang/Object; ; 0x3bc
        6e30??00????   // invoke-virtual {v0, v3, v1}, Ljava/lang/reflect/Method.invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
        0e00           // return-void
        0d00           // move-exception v0
        28fe           // goto 0x00002984
    }

    /**
        private byte[] mMuKJXDuYr(byte[] a, byte[] key) {
            byte[] out = new byte[a.length];
            for (int i = 0; i < a.length; i++) {
                out[i] = (byte) (a[i] ^ key[i % key.length]);
            }
            return out;
        }
    */
    $xor_key = {
       21 ??         //  array-length        v2, p1
       23 ?? 17 00   //  new-array           v1, v2, [B
       12 00         //  const/4             v0, 0
       21 ??         //  array-length        v2, p1
       35 ?? ?? 00   //  if-ge               v0, v2, :2A
       48 02 ?? 00   //  aget-byte           v2, p1, v0
       21 ?3         //  array-length        v3, p2
       94 03 ?? ??   //  rem-int             v3, v0, v3
       48 03 ?? ??   //  aget-byte           v3, p2, v3
       B7 ??         //  xor-int/2addr       v2, v3
       8D ??         //  int-to-byte         v2, v2
       4F 02 ?? ??   //  aput-byte           v2, v1, v0
       D8 00 ?? ??   //  add-int/lit8        v0, v0, 1
       28 F0         //  goto                :8
       11 01         //  return-object       v1
    }

  condition:
    $attachBaseContextOpcodes and $xor_key and 3 of ($str_*)
}
