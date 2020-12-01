/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pancake
    Rule name: PokemonGo
    Rule id: 1716
    Created at: 2016-08-02 16:23:13
    Updated at: 2016-08-02 16:23:35
    
    Rating: #0
    Total detections: 579
*/

import "androguard"

rule pokemongo : fake
{
	meta:
		description = "This rule detects fakes Pokemon Go apps "
		sample = ""

	condition:
		(androguard.package_name("com.nianticlabs.pokemongo") or androguard.app_name("Pokemon GO")) and not
		androguard.certificate.sha1("321187995BC7CDC2B5FC91B11A96E2BAA8602C62")
		
}
