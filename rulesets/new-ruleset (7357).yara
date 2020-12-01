/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: meili
    Rule name: New Ruleset
    Rule id: 7357
    Created at: 2020-11-17 14:20:29
    Updated at: 2020-11-17 14:20:45
    
    Rating: #1
    Total detections: 0
*/

rule music_player_apk
{
meta:
	description = "rule to uniquely identify apk"
strings:
	$a = ".field public static final ic_launcher_music:I = 0x7f050006"
	$b = ".field public static final ic_launcher_music_jooxy:I = 0x7f050007"
	$c = ".method public constructor <init>(Ljava/util/List;Lokhttp3/internal/connection/StreamAllocation;Lokhttp3/internal/http/HttpCodec;Lokhttp3/internal/connection/RealConnection;ILokhttp3/Request;Lokhttp3/Call;Lokhttp3/EventListener;III)V"
	$d = ".method public constructor <init>(Lokhttp3/ConnectionPool;Lokhttp3/Address;Lokhttp3/Call;Lokhttp3/EventListener;Ljava/lang/Object;)V"
	$e = ".method public constructor <init>(Lokhttp3/Address;Lokhttp3/internal/connection/RouteDatabase;Lokhttp3/Call;Lokhttp3/EventListener;)V"
	$f = ".method public constructor <init>(Lokhttp3/Request;Lokhttp3/WebSocketListener;Ljava/util/Random;J)V"
	$g = ".method constructor <init>(Lokhttp3/EventListener;)V"
	$h = ".method public constructor <init>(Landroid/content/Context;Landroid/os/Looper;Landroid/location/LocationManager;Landroid/location/LocationListener;)V"
	$i = "com.securicy.bubblewrapgame"

condition:
	$a and $b and $c and $d and $e and $f and $g and $h and $i
}
