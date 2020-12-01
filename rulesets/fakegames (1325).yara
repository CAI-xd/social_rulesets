/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: FakeGames
    Rule id: 1325
    Created at: 2016-03-30 15:30:56
    Updated at: 2016-03-30 15:47:45
    
    Rating: #0
    Total detections: 7
*/

rule fakeGames
{
	meta:
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		google_play = "https://play.google.com/store/apps/developer?id=Dawerominza"

	strings:
		$a = "http://ggd.prnlivem.com/frerr.php"
		$b = "Lcom/gte/fds/j/a;"

	condition:
		any of them
		
}
