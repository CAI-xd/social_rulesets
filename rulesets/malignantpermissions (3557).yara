/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jcarneiro
    Rule name: MalignantPermissions
    Rule id: 3557
    Created at: 2017-09-06 15:00:38
    Updated at: 2017-11-02 14:29:31
    
    Rating: #0
    Total detections: 298785
*/

import "androguard"


rule testRule
{

	condition:
		androguard.permission(/com.massage.aptoide.permission.C2D_MESSAGE/) or
		androguard.permission(/android.permission.SET_ANIMATION_SCALE/) or
		androguard.permission(/org.catrobat.catroid.generated27539.permission.C2D_MESSAGE/) or
		androguard.permission(/com.massage.aptoide.permission.C2D_MESSAGE/) or
		androguard.permission(/android.permission.READ_APP_BADGE/) or
		androguard.permission(/me.everything.badger.permission.BADGE_COUNT_READ/) or
		androguard.permission(/me.everything.badger.permission.BADGE_COUNT_WRITE/) or
		androguard.permission(/com.mytriber.me.Tb565fa76620d4290a8d317d3f38e82da.permission.C2D_MESSAGE/) or
		androguard.permission(/com.gamedevltd.modernstrike.bgtdfg.permission.C2D_MESSAGE/) or
		androguard.permission(/com.jumpgames.pacificrim.permission.C2D_MESSAGE/) or
		androguard.permission(/io.wifimap.wifimap.gcm.permission.C2D_MESSAGE/) or
		androguard.permission(/nullsclash.night.rel.permission.C2D_MESSAGE/) or
		androguard.permission(/com.yd.android.mtstrikeru.permission.JPUSH_MESSAGE/) or
		androguard.permission(/com.yd.android.mtstrikeru.permission.C2D_MESSAGE/) or
		androguard.permission(/com.hecorat.screenrecorder.free.permission.C2D_MESSAGEdf/) or
		androguard.permission(/com.sec.enterprise.permission.MDM_PROXY_ADMIN_INTERNAL/) or
		androguard.permission(/android.permission.BIND_DEVICE_ADMIN/) or
		androguard.permission(/android.permission.sec.ENTERPRISE_DEVICE_ADMIN/) or
		androguard.permission(/com.sec.enterprise.knox.permission.KNOX_ATTESTATION/) or
		androguard.permission(/android.permission.sec.MDM_APP_BACKUP/) or
		androguard.permission(/com.sec.enterprise.mdm.permission.BROWSER_PROXY/) or
		androguard.permission(/android.permission.ACCESS_MOCK_LOCATION/) or
		androguard.permission(/android.permission.SET_PROCESS_LIMIT/) or
		androguard.permission(/com.sec.enterprise.knox.cloudmdm.smdms.permission.SAMSUNG_MDM_SERVICE/) or
		androguard.permission(/android.permission.sec.MDM_APP_MGMT/) or
		androguard.permission(/android.permission.sec.MDM_APP_PERMISSION_MGMT/) or
		androguard.permission(/android.permission.sec.MDM_BLUETOOTH/) or
		androguard.permission(/android.permission.sec.MDM_INVENTORY/) or
		androguard.permission(/android.permission.sec.MDM_EXCHANGE/) or
		androguard.permission(/android.permission.sec.MDM_ROAMING/) or
		androguard.permission(/android.permission.sec.MDM_WIFI/) or
		androguard.permission(/android.permission.sec.MDM_SECURITY/) or
		androguard.permission(/android.permission.sec.MDM_HW_CONTROL/) or
		androguard.permission(/android.permission.sec.MDM_RESTRICTION/) or
		androguard.permission(/android.permission.sec.MDM_LOCATION/) or
		androguard.permission(/android.permission.sec.MDM_CALLING/) or
		androguard.permission(/android.permission.sec.MDM_EMAIL/) or
		androguard.permission(/android.permission.sec.MDM_VPN/) or
		androguard.permission(/android.permission.sec.MDM_APN/) or
		androguard.permission(/android.permission.sec.MDM_PHONE_RESTRICTION/) or
		androguard.permission(/android.permission.sec.MDM_BROWSER_SETTINGS/) or
		androguard.permission(/android.permission.sec.MDM_DATE_TIME/) or
		androguard.permission(/android.permission.sec.MDM_ENTERPRISE_VPN/) or
		androguard.permission(/android.permission.sec.MDM_FIREWALL/) or
		androguard.permission(/android.permission.sec.MDM_REMOTE_CONTROL/) or
		androguard.permission(/android.permission.sec.MDM_KIOSK_MODE/) or
		androguard.permission(/android.permission.sec.MDM_AUDIT_LOG/) or
		androguard.permission(/android.permission.sec.MDM_CERTIFICATE/) or
		androguard.permission(/android.permission.sec.MDM_SMARTCARD/) or
		androguard.permission(/android.permission.sec.MDM_SEANDROID/) or
		androguard.permission(/android.permission.sec.MDM_LDAP/) or
		androguard.permission(/android.permission.sec.MDM_LOCKSCREEN/) or
		androguard.permission(/android.permission.sec.MDM_GEOFENCING/) or
		androguard.permission(/android.permission.sec.MDM_BLUETOOTH_SECUREMODE/) or
		androguard.permission(/android.permission.sec.MDM_MULTI_USER_MGMT/) or
		androguard.permission(/android.permission.sec.MDM_LICENSE_LOG/) or
		androguard.permission(/android.permission.sec.MDM_DUAL_SIM/) or
		androguard.permission(/android.permission.sec.MDM_ENTERPRISE_SSO/) or
		androguard.permission(/android.permission.sec.MDM_ENTERPRISE_ISL/) or
		androguard.permission(/android.permission.sec.MDM_ENTERPRISE_CONTAINER/) or
		androguard.permission(/android.permission.sec.ENTERPRISE_MOUNT_UNMOUNT_ENCRYPT/) or
		androguard.permission(/android.permission.sec.ENTERPRISE_CONTAINER/) or
		androguard.permission(/com.sec.enterprise.knox.KNOX_GENERIC_VPN/) or
		androguard.permission(/com.sec.enterprise.knox.permission.KNOX_DEACTIVATE_LICENSE/) or
		androguard.permission(/com.sec.enterprise.knox.permission.KNOX_CCM/) or
		androguard.permission(/android.permission.sec.MDM_UMC_INTERNAL/) or
		androguard.permission(/com.sec.enterprise.knox.permission.KNOX_CERTENROLL/) or
		androguard.permission(/com.sec.enterprise.mdm.permission.MDM_SSO/) or
		androguard.permission(/com.sec.enterprise.knox.KNOX_CONTAINER_VPN/) or
		androguard.permission(/com.samsung.android.gencertservice.permission.SERVICE_BIND/) or
		androguard.permission(/com.sec.android.SAMSUNG_AASASERVICE/) or
		androguard.permission(/com.fde.avpevolution.bfgtwe.permission.C2D_MESSAGE/) or
		androguard.permission(/com.rsupport.mobizen.live.permission.C2D_MESSAGE/) or
		androguard.permission(/com.gameloft.android.ANMP.GloftLBCR.permission.C2D_MESSAGEzy/) or
		androguard.permission(/glshare.permission.ACCESS_SHARED_DATAzy/) or
		androguard.permission(/com.paradoxplaza.prisonarchitect.permission.C2D_MESSAGE/) or
		androguard.permission(/com.gameloft.android.ANMP.GloftG4HM.bddf.permission.C2D_MESSAGE/) or
		androguard.permission(/android.launcher.permission.INSTALL_SHORTCUT/) or
		androguard.permission(/com.kilooclash.clashofclans.permission.C2D_MESSAGE/) or
		androguard.permission(/com.rockstargames.bully.bfgtwe.permission.C2D_MESSAGE/) or
		androguard.permission(/com.giantssoftware.fs18.google.permission.C2D_MESSAGE/) or
		androguard.permission(/com.tct.launcher.permission.READ_SETTINGS/) or
		androguard.permission(/com.tct.launcher.permission.WRITE_SETTINGS/) or
		androguard.permission(/com.tct.launcher.permission.RECEIVE_LAUNCH_BROADCASTS/) or
		androguard.permission(/com.tct.launcher.permission.RECEIVE_FIRST_LOAD_BROADCAST/) or
		androguard.permission(/android.permission.ACCESS_OTA_DATA/) or
		androguard.permission(/com.tct.email.permission.ACCESS_PROVIDER/) or
		androguard.permission(/com.tct.launcher.permission.C2D_MESSAGE/) or
		androguard.permission(/com.supercell.clashofclans.permission.C2D_MESSAGEpgxu/)
}
