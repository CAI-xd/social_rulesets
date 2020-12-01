/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Throwaway192554
    Rule name: New Ruleset
    Rule id: 7341
    Created at: 2020-11-16 18:22:37
    Updated at: 2020-11-18 11:48:29
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule Reciever
{
	meta:
		description = "Rule seeks to detect certain reciever (see PReciever and OReciever in sample) classes in order to detect apps similair to this one."
		sample = "e970b8ab54cf6c1e1c7d06440867ed4e40dfa277cedb38796ac8ae30380df512"

	strings:
		$a = "Receiver;->onReceive(Landroid/content/Context;Landroid/content/Intent;)V"
		$b = "Receiver;-><init>()V"

	condition:
		$a and $b and filesize == 471 and (
		androguard.permission(/android.permission.BROADCAST_WAP_PUSH/) 
			or androguard.permission(/android.permission.BROADCAST_SMS/)
		)
}
