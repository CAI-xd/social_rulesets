/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob16682
    Rule name: New Ruleset
    Rule id: 5748
    Created at: 2019-07-12 17:14:36
    Updated at: 2019-07-12 17:21:06
    
    Rating: #0
    Total detections: 0
*/

rule Agent_Smith
{
	strings:
		$a1 = "whatsapp"
    	$a2 = "lenovo.anyshare.gps"
    	$a3 = "mxtech.videoplayer.ad"
    	$a4 = "jio.jioplay.tv"
    	$a5 = "jio.media.jiobeats"
    	$a6 = "jiochat.jiochatapp"
    	$a7 = "jio.join"
    	$a8 = "good.gamecollection"
    	$a9 = "opera.mini.native"
   		$a10 = "startv.hotstar"
    	$a11 = "meitu.beautyplusme"
    	$a12 = "domobile.applock"
    	$a13 = "touchtype.swiftkey"
    	$a14 = "flipkart.android"
    	$a15 = "cn.xender"
    	$a16 = "eterno"
    	$a17 = "truecaller"

	condition:
		all of them
		
}
