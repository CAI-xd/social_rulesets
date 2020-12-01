/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: AppGuard Toast Korea Packer
    Rule id: 5249
    Created at: 2019-02-02 22:49:47
    Updated at: 2019-12-25 21:14:58
    
    Rating: #0
    Total detections: 12
*/

import "androguard"
import "file"
import "cuckoo"


rule appguard_kr : packer
{
  meta:
    description = "AppGuard (TOAST-NHNent)"
    url         = "https://docs.toast.com/en/Security/AppGuard/en/Overview/"
    url2        = "https://www.toast.com/service/security/appguard"
    sample      = "80ac3e9d3b36613fa82085cf0f5d03b58ce20b72ba29e07f7c744df476aa9a92"


	strings:
    // package com.nhnent.appguard;
    $a1 = "assets/classes.jet"
    $a2 = "assets/classes.zip"
    $a3 = "assets/classes2.jet"
    $a4 = "assets/classes2.zip"
    $a5 = "assets/classes3.jet"
    $a6 = "assets/classes3.zip"
    $b1 = "lib/armeabi-v7a/libloader.so"
    $b2 = "lib/x86/libloader.so"
    $b3 = "lib/armeabi-v7a/libdiresu.so"
    $b4 = "lib/x86/libdiresu.so"
    $c1 = "assets/m7a"
    $c2 = "assets/m8a"
    $c3 = "assets/agconfig"    //appguard cfg?
    $c4 = "assets/agmetainfo"

  condition:
    2 of ($a*) and 1 of ($b*) and 1 of ($c*)
	}
