/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: raydentseng
    Rule name: New Ruleset
    Rule id: 7343
    Created at: 2020-11-16 20:11:42
    Updated at: 2020-11-16 20:43:08
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule Downloader
{
    meta:
        description = "This rule detects the Downloader app from Koodous"

    strings: 
    $md5 = {226b9a8e0da1a93fba65247a73ae6f8504f6c65a97336c4a3a2db9fb4f1df6a6}
	$sha1 = {896bdf295a7ee8089349426b7950615f2a0d41e9}
	$package = "com.ossibussoftware.deadpixeltest"
	$method = "com/google/android/gms/ads/identifier/AdvertisingIdClient$Info;->isLimitAdTrackingEnabled()Z"
        
    condition:
        $md5 and $sha1 and $package and $method
        
}
