@setlocal enableextensions
title BokaRoka's Safe-to-Remove BLOATWARE APK's
color 1b
taskkill /f /im adb.exe
adb devices
:: Removes Transsion Phone Manager from the Doze mode whitelist to prevent system maintenance tasks while the device is idle
adb shell dumpsys deviceidle sys-whitelist -com.transsion.phonemanager
:: Removes Google Quick Search Box (Google Search) from the Doze mode whitelist to restrict background activity when idle
adb shell dumpsys deviceidle sys-whitelist -com.google.android.googlequicksearchbox
:: Removes Google Location History from the Doze mode whitelist to prevent background location tracking when idle
adb shell dumpsys deviceidle sys-whitelist -com.google.android.gms.location.history
:: Removes YouTube from the Doze mode whitelist to stop background updates and notifications while the device is idle
adb shell dumpsys deviceidle sys-whitelist -com.google.android.youtube
:: Removes Google Text-to-Speech from the Doze mode whitelist to reduce unnecessary background activity in idle mode
adb shell dumpsys deviceidle sys-whitelist -com.google.android.tts
:: Removes Facebook Services from the Doze mode whitelist to stop background tasks and notifications during idle time
adb shell dumpsys deviceidle sys-whitelist -com.facebook.services
:: Removes Facebook app from the Doze mode whitelist to limit background updates and battery drain while idle
adb shell dumpsys deviceidle sys-whitelist -com.facebook.katana
:: Removes Facebook App Manager from the Doze mode whitelist, preventing it from managing Facebook-related app updates and background activities while idle
adb shell dumpsys deviceidle sys-whitelist -com.facebook.appmanager
:: Removes Facebook System Services from the Doze mode whitelist, stopping it from running system-level Facebook tasks while the device is idle
adb shell dumpsys deviceidle sys-whitelist -com.facebook.system
:: Removes Facebook Lite from the Doze mode whitelist, restricting its background activity and updates while idle
adb shell dumpsys deviceidle sys-whitelist -com.facebook.lite
:: Removes Scorpio Security from the Doze mode whitelist to restrict its background activity and save battery in idle mode
adb shell dumpsys deviceidle sys-whitelist -com.scorpio.securitycom
:: Adds 1DM+ Downloader App to the Doze mode whitelist, allowing it to bypass Doze and continue downloads even when idle
adb shell dumpsys deviceidle whitelist +idm.internet.download.manager.plus\
adb shell pm enable com.google.android.apps.nbu.files
echo Do you want to Begin?
pause
adb devices
cls
for %%X in (
"com.netflix.mediaclient"
"com.netflix.partner.activation"
"com.netflix.mediaclient.kids"
"com.netflix.ninja"
"com.linkedin.android"
"com.lazada.android"
"cn.wps.moffice_eng"
"com.1tapcleaner"
"com.alibaba.aliexpresshd"
"com.amazon.appmanager"
"com.amazon.mshop.android.shopping"
"com.android.bbkcalculator"
"com.android.bbkclock"
"com.android.bbklog"
"com.android.bbkmusic"
"com.android.bbksoundrecorder"
"com.android.browser"
"com.android.dreams.basic"
"com.android.dreams.phototable"
"com.android.egg"
"com.android.email.partnerprovider"
"com.android.fmradio"
"com.android.hotwordenrollment.okgoogle"
"com.android.notes"
"com.android.providers.partnerbookmarks"
"com.android.sales"
"com.android.systemui.plugin.globalactions.wallet"
"com.android.traceur"
"com.avast.android.cleaner"
"com.boost.cleaner"
"com.clean.boost"
"com.clean.cache"
"com.cleanmaster.lite"
"com.cleanmaster.pro"
"com.cleanmyandroid"
"com.cleanup"
"com.dianxinos.dxbs"
"com.droid.optimizer"
"com.file.cleaner"
"com.google.android.apps.chromecast.app"
"com.google.android.apps.adm"
"com.google.android.apps.googleassistant"
"com.google.android.apps.magazines"
"com.google.android.apps.nbu.paisa.user"
"com.google.android.apps.payments"
"com.google.android.apps.restore"
"com.google.android.apps.searchlite"
"com.google.android.apps.subscriptions.red"
"com.google.android.apps.tachyon"
"com.google.android.apps.wallet"
"com.google.android.apps.walletnfcrel"
"com.google.android.apps.youtube.music"
"com.google.android.calendar"
"com.google.android.feedback"
"com.google.android.gms.location.history"
"com.google.android.gms.wallet"
"com.google.android.keep"
"com.google.android.marvin.talkback"
"com.google.android.music"
"com.google.android.onetimeinitializer"
"com.google.android.partnersetup"
"com.google.android.printservice.recommendation"
"com.google.android.projection.gearhead"
"com.google.android.syncadapters.calendar"
"com.google.android.videos"
"com.google.ar.core"
"com.google.ar.lens"
"com.google.vr.vrcore"
"com.icebox.powerclean"
"com.icleaner"
"com.junk.cleaner"
"com.master.cleaner"
"com.panda.cachecleaner"
"com.phone.cleaner"
"com.smartcleaner"
"com.speed.booster.cleaner"
"com.super.cleaner"
"com.superjunkcleaner"
"com.symantec.cleaner"
"com.whatsapp.cleaner"
"google.android.printservice.recommendation"
) do (
adb shell pm uninstall %%X
adb shell pm uninstall --user 0 %%X
)
taskkill /f /im adb.exe
adb start-server
adb devices
echo	Removing part 2...
cls
for %%X in (
"coloros.gamespaceui"
"com.app.market"
"com.asa.xnotelite"
"com.baidu.duersdk.opensdk"
"com.bbk.account"
"com.bbk.calendar"
"com.bbk.cloud"
"com.bbk.facewake"
"com.bbk.iqoo.logsystem"
"com.bbk.photoframewidget"
"com.bbk.scene.indoor"
"com.bbk.superpowersave"
"com.bbk.theme"
"com.bbk.theme.resources"
"com.bbk.updater"
"com.caf.fmradio"
"com.calpa.share"
"com.coloros.activation"
"com.coloros.aftersalesservice"
"com.coloros.assistantscreen"
"com.coloros.avastofferwall"
"com.coloros.backuprestore"
"com.coloros.backuprestore.remoteservice"
"com.coloros.childrenspace"
"com.coloros.cloud"
"com.coloros.compass2"
"com.coloros.floatassistant"
"com.coloros.focusmode"
"com.coloros.healthcheck"
"com.coloros.healthservice"
"com.coloros.karaoke"
"com.coloros.musiclink"
"com.coloros.onekeylockscreen"
"com.coloros.oppomultiapp"
"com.coloros.oshare"
"com.coloros.phonedual"
"com.coloros.phonemanager"
"com.coloros.safesdkproxy"
"com.coloros.scenemode"
"com.coloros.securepay"
"com.coloros.smartdrive"
"com.coloros.smartsidebar"
"com.coloros.soundrecorder"
"com.coloros.speechassist"
"com.coloros.systemclone"
"com.coloros.tips"
"com.coloros.translate.engine"
"com.coloros.video"
"com.coloros.videoeditor"
"com.coloros.wallet"
"com.coloros.wallpapers"
"com.coloros.weather"
"com.coloros.weather.service"
"com.coloros.weather.widget"
"com.coloros.weather2"
"com.coloros.widget.smallweather"
"com.finrealtech.payments"
"com.nearme.gamecenter"
"com.heytap.accessory"
"com.heytap.browser"
"com.heytap.cloud"
"com.heytap.colorfulengine"
"com.heytap.habit.analysis"
"com.heytap.market"
"com.heytap.mcs"
"com.heytap.pictorial"
"com.heytap.quickgame"
"com.heytap.soloop"
"com.heytap.synergy"
"com.heytap.themestore"
"com.heytap.usercenter"
"com.nearme.themespace"
"com.oppo.atlas"
"com.oppo.clonephone"
"com.oppo.feedback"
"com.oppo.hotapps"
"com.oppo.hotgames"
"com.oppo.market"
"com.oppo.operationmanual"
"com.oppo.opperationmanual"
"com.oppo.quicksearchbox"
"com.oppo.store"
"com.oppoex.afterservice"
"com.reallytek.wg"
"com.realme.community"
"com.realme.lab"
"com.realme.link"
"com.realme.movieshot"
"com.realme.securitycheck"
"com.realmecomm.app"
"com.realmepay.payments"
"com.realmestore.app"
) do (
adb shell pm uninstall %%X
adb shell pm uninstall --user 0 %%X
)
taskkill /f /im adb.exe
adb start-server
adb devices
echo	Removing part 3...
cls
for %%X in (
"com.samsung.android.aircommandmanager"
"com.samsung.android.app.aodservice"
"com.samsung.android.app.camera.sticker.facear.preload"
"com.samsung.android.app.camera.sticker.facearavatar.preload"
"com.samsung.android.app.camera.sticker.facearexpression.preload"
"com.samsung.android.app.camera.sticker.facearframe.preload"
"com.samsung.android.app.camera.sticker.stamp.preload"
"com.samsung.android.app.ledbackcover"
"com.samsung.android.app.routines"
"com.samsung.android.app.sbrowseredge"
"com.samsung.android.app.social"
"com.samsung.android.app.spage"
"com.samsung.android.app.tips"
"com.samsung.android.app.vrsetupwizardstub"
"com.samsung.android.app.watchmanagerstub"
"com.samsung.android.ardrawing"
"com.samsung.android.aremoji"
"com.samsung.android.authfw"
"com.samsung.android.bixby.agent"
"com.samsung.android.bixby.agent.dummy"
"com.samsung.android.bixby.service"
"com.samsung.android.bixby.wakeup"
"com.samsung.android.bixbyvision.framework"
"com.samsung.android.da.daagent"
"com.samsung.android.drivelink.stub"
"com.samsung.android.email.provider"
"com.samsung.android.emojiupdater"
"com.samsung.android.fast"
"com.samsung.android.game.gamehome"
"com.samsung.android.game.gametools"
"com.samsung.android.game.gos"
"com.samsung.android.gametuner.thin"
"com.samsung.android.hmt.vrshell"
"com.samsung.android.hmt.vrsvc"
"com.samsung.android.kidsinstaller"
"com.samsung.android.mateagent"
"com.samsung.android.voc"
"com.samsung.android.samsungpass"
"com.samsung.android.samsungpassautofill"
"com.samsung.android.service.aircommand"
"com.samsung.android.service.livedrawing"
"com.samsung.android.service.peoplestripe"
"com.samsung.android.spay"
"com.samsung.android.spayfw"
"com.samsung.android.stickercenter"
"com.samsung.android.visionintelligence"
"com.samsung.desktopsystemui"
"com.samsung.smt"
"com.samsung.sree"
"com.samsung.systemui.bixby2"
"com.samsung.vvm"
"com.samsung.vvm.se"
"com.sec.android.widgetapp.samsungapps"
"com.sec.mygalaxy.NEBangs"
"com.sec.android.app.dexonpc"
"com.sec.android.app.kidshome"
"com.sec.android.app.sbrowser"
"com.sec.android.cover.ledcover"
"com.sec.android.daemonapp"
"com.sec.android.desktopcommunity"
"com.sec.android.desktopmode.uiservice"
"com.sec.android.easymover.agent"
"com.sec.android.easyonehand"
"com.sec.android.mimage.avatarstickers"
"samsung.android.app.aodservice"
"samsung.android.app.dressroom"
"samsung.android.app.routines"
"samsung.android.app.social"
"samsung.android.app.spage"
"samsung.android.app.watchmanagerstub"
"samsung.android.ardrawing"
"samsung.android.authfw"
"samsung.android.bixby.agent"
"samsung.android.bixby.agent.dummy"
"samsung.android.bixby.service"
"samsung.android.bixby.wakeup"
"samsung.android.bixbyvision.framework"
"samsung.android.drivelink.stub"
"samsung.android.email.provider"
"samsung.android.game.gamehome"
"samsung.android.game.gametools"
"samsung.android.game.gos"
"samsung.android.gametuner.thin"
"samsung.android.mateagent"
"samsung.android.oneconnect"
"samsung.android.samsungpass"
"samsung.android.samsungpassautofill"
"samsung.android.scloud"
"samsung.android.sdk.handwriting"
"samsung.android.sdk.professionalaudio.utility.jammonitor"
"samsung.android.service.aircommand"
"samsung.android.service.livedrawing"
"samsung.android.spay"
"samsung.android.spayfw"
"samsung.android.svoiceime"
"samsung.android.universalswitch"
"samsung.android.visioncloudagent"
"samsung.android.visionintelligence"
"samsung.android.voc"
"samsung.android.widgetapp.yahooedge.finance"
"samsung.android.widgetapp.yahooedge.sport"
"samsung.app.highlightplayer"
"samsung.ecomm.global"
"samsung.safetyinformation"
"samsung.storyservice"
"sec.android.widgetapp.samsungapps"
) do (
adb shell pm uninstall %%X
adb shell pm uninstall --user 0 %%X
)
cls
taskkill /f /im adb.exe
adb start-server
adb devices
echo	Removing part 4...
cls
for %%X in (
"com.asus.mobilemanager"
"com.coloros.phonemanager"
"com.daemon.shelper"
"com.dsi.ant.plugins.antplus"
"com.dsi.ant.sample.acquirechannels"
"com.dsi.ant.server"
"com.dsi.ant.service.socket"
"com.ebay.carrier"
"com.ebay.mobile"
"com.enhance.gameservice"
"com.facebook.appmanager"
"com.facebook.services"
"com.facebook.system"
"com.finshell.fin"
"com.finshell.pay"
"com.finshell.wallet"
"com.coloros.wallet"
"com.funbase.xradio"
"com.glance.internet"
"com.goodix.gftest"
"com.huaqin.diaglogger"
"com.ibimuyu.lockscreen"
"com.idea.questionnaire"
"com.ino.cleanmaster"
"com.ino.weatherapp"
"com.iqoo.powersaving"
"com.iqoo.secure"
"com.lenovo.anyshare"
"com.lenovo.component.translationservice"
"com.lenovo.gameworldphone"
"com.lenovo.ue.device"
"com.lenovo.updateassist"
"com.lge.cleaner"
"com.mediatek.atmwifimeta"
"com.mediatek.gnssdebugreport"
"com.mediatek.mdmconfig"
"com.mfashiongallery.emag"
"com.micredit.in"
"com.microsoft.skydrive"
"com.milink.service"
"com.mipay.wallet.id"
"com.mipay.wallet.in"
"com.nearme.statistics.rom"
"com.nt36xxxtouchscreen.deltadiff"
"com.oneplus.cleaner"
"com.oplus.aod"
"com.oplus.apprecover"
"com.oplus.atlas"
"com.oplus.blacklistapp"
"com.oplus.cast"
"com.oplus.cosa"
"com.oplus.crashbox"
"com.oplus.deepthinker"
"com.oplus.healthservice"
"com.oplus.lfeh"
"com.oplus.logkit"
"com.oplus.nhs"
"com.oplus.pay"
"com.oplus.postmanservice"
"com.oplus.romupdate"
"com.oplus.statistics.rom"
"com.oplus.stdid"
"com.oplus.synergy"
"com.opos.cs"
"com.os.docvault"
"com.qiyi.video.loenovo"
"com.qti.confuridialer"
"com.qti.dpmserviceapp"
"com.qti.qualcomm.datastatusnotification"
"com.qti.qualcomm.deviceinfo"
"com.qti.xdivert"
"com.qualcomm.embms"
"com.qualcomm.qti.autoregistration"
"com.qualcomm.qti.callfeaturessetting"
"com.qualcomm.qti.ims"
"com.qualcomm.qti.lpa"
"com.qualcomm.qti.modemtestmode"
"com.qualcomm.qti.qms.service.telemetry"
"com.qualcomm.qti.smq"
"com.qualcomm.qti.uim"
"com.redteamobile.roaming"
"com.rlk.mi"
"com.rlk.weathers"
"com.rongcard.eid"
"com.rongcard.eidapi"
"com.samsung.android.app.galaxyfinder"
"com.sonyericsson.android.xperiadiagnostics"
"com.vivo.phoneassistant"
"facebook.appmanager"
"facebook.services"
"facebook.system"
) do (
adb shell pm uninstall %%X
adb shell pm uninstall --user 0 %%X
)
cls
taskkill /f /im adb.exe
adb start-server
adb devices
for %%X in (
"com.scorpio.securitycom"
"com.smartlife.nebula"
"com.sprd.logmanager"
"com.spreadtrum.proxy.nfwlocation"
"com.talpa.hibrowser"
"com.talpa.share"
"com.tencent.igxiaomi"
"com.tencent.soter.soterserver"
"com.transsion.agingfunction"
"com.transsion.aibox"
"com.transsion.aivoiceassistant"
"com.transsion.antipeep"
"com.transsion.antitheft"
"com.transsion.ar.arcanvas"
"com.transsion.arbusiness.infinix"
"com.transsion.batterylab"
"com.transsion.beezedit"
"com.transsion.bookmarks"
"com.transsion.calendar"
"com.transsion.carlcare"
"com.transsion.childmode"
"com.transsion.datatransfer"
"com.transsion.dualapp"
"com.transsion.faceid"
"com.transsion.faceidsub"
"com.transsion.fmradio"
"com.transsion.hamal"
"com.transsion.health"
"com.transsion.healthlife"
"com.transsion.infinix.xclub"
"com.transsion.insync"
"com.transsion.kolun.assistant"
"com.transsion.letswitch"
"com.transsion.magazineservice.xos"
"com.transsion.magicfont"
"com.transsion.magicshow"
"com.transsion.microintelligence"
"com.transsion.multiwindow"
"com.transsion.notebook"
"com.transsion.os.typeface"
"com.transsion.phonemanager"
"com.transsion.phonemaster"
"com.transsion.plat.appupdate"
"com.transsion.repaircard"
"com.transsion.scanningrecharger"
"com.transsion.smartpanel"
"com.transsion.statisticalsales"
"com.transsion.systemupdate"
"com.transsion.tecnospot"
"com.transsion.thunderback"
"com.transsion.trancare"
"com.transsion.videocallenhancer"
"com.transsion.wezone"
"com.transsion.wifiplaytogether"
"com.transsnet.store"
"com.trassion.infinix.xclub"
"com.trustonic.teeservice"
"com.verizon.remotesimlock"
) do (
adb shell pm uninstall %%X
adb shell pm uninstall --user 0 %%X
)
cls
taskkill /f /im adb.exe
adb start-server
adb devices
for %%X in (
"android.autoinstalls.config.xiaomi.daisy"
"com.baidu.input_vivo"
"com.kikaoem.vivo.qisiemoji.inputmethod"
"com.mi.android.globalpersonalassistant"
"com.mi.global.bbs"
"com.mi.globalbrowser"
"com.mi.globaltrendnews"
"com.mi.health"
"com.mi.webkit.core"
"com.milink.service"
"com.miui.analytics"
"com.miui.aod"
"com.miui.audioeffect"
"com.miui.audiomonitor"
"com.miui.backup"
"com.miui.bugreport"
"com.miui.calculator"
"com.miui.cit"
"com.miui.cleanmaster"
"com.miui.cloudbackup"
"com.miui.cloudservice"
"com.miui.cloudservice.sysbase"
"com.miui.compass"
"com.miui.contentcatcher"
"com.miui.daemon"
"com.miui.enbbs"
"com.miui.extraphoto"
"com.miui.fm"
"com.miui.fmservice"
"com.miui.freeform"
"com.miui.greenguard"
"com.miui.huanji"
"com.miui.hybrid"
"com.miui.hybrid.accessory"
"com.miui.klo.bugreport"
"com.miui.maintenancemode"
"com.miui.micloudsyn"
"com.miui.micloudsync"
"com.miui.miservice"
"com.miui.mishare.connectivity"
"com.miui.misound"
"com.miui.miwallpaper"
"com.miui.miwallpaper.earth"
"com.miui.miwallpaper.mars"
"com.miui.msa.global"
"com.miui.newmidrive"
"com.miui.nextpay"
"com.miui.notes"
"com.miui.personalassistant"
"com.miui.phrase"
"com.miui.player"
"com.miui.qr"
"com.miui.smsextra"
"com.miui.spock"
"com.miui.systemAdSolution"
"com.miui.systemui.carriers.overlay"
"com.miui.touchassistant"
"com.miui.translation.kingsoft"
"com.miui.translation.xmcloud"
"com.miui.translation.youdao"
"com.miui.translationservice"
"com.miui.userguide"
"com.miui.virtualsim"
"com.miui.voiceassist"
"com.miui.voicetrigger"
"com.miui.vsimcore"
"com.miui.weather2"
"com.miui.weather"
"com.miui.wmsvc"
"com.miui.yellowpage"
"com.miui.zman"
"com.mobiletools.systemhelper"
"com.vivo.agent"
"com.vivo.appfilter"
"com.vivo.appstore"
"com.vivo.assistant"
"com.vivo.browser"
"com.vivo.carmode"
"com.vivo.collage"
"com.vivo.compass"
"com.vivo.doubleinstance"
"com.vivo.doubletimezoneclock"
"com.vivo.dream.weather"
"com.vivo.easyshare"
"com.vivo.email"
"com.vivo.ewarranty"
"com.vivo.favorite"
"com.vivo.floatingball"
"com.vivo.fmradio"
"com.vivo.fuelsummary"
"com.vivo.game"
"com.vivo.gamecube"
"com.vivo.gametrain"
"com.vivo.gamewatch"
"com.vivo.globalsearch"
"com.vivo.hiboard"
"com.vivo.livewallpaper.coffeetime"
"com.vivo.livewallpaper.coralsea"
"com.vivo.livewallpaper.floatingcloud"
"com.vivo.livewallpaper.galaxy"
"com.vivo.livewallpaper.silk"
"com.vivo.magazine"
"com.vivo.minscreen"
"com.vivo.motormode"
"com.vivo.multinlp"
"com.vivo.numbermark"
"com.vivo.pushservice"
"com.vivo.safecenter"
"com.vivo.safecentercom.vivo.scanner"
"com.vivo.scanner"
"com.vivo.share"
"com.vivo.smartkey"
"com.vivo.smartmultiwindow"
"com.vivo.tips"
"com.vivo.translator"
"com.vivo.unionpay"
"com.vivo.upnpserver"
"com.vivo.video.floating"
"com.vivo.videoeditor"
"com.vivo.vivokaraoke"
"com.vivo.weather"
"com.vivo.weather.provider"
"com.vivo.website"
"com.vivo.widget.calendar"
"com.vlife.vivo.wallpaper"
"com.wapi.wapicertmanage"
"com.wsomacp"
"com.xiaomi.ab"
"com.xiaomi.aiasst.service"
"com.xiaomi.gamecenter"
"com.xiaomi.gamecenter.sdk.service"
"com.xiaomi.glgm"
"com.xiaomi.hm.health"
"com.xiaomi.joyose"
"com.xiaomi.mi_connect_service"
"com.xiaomi.micloud.sdk"
"com.xiaomi.midrop"
"com.xiaomi.migameservice"
"com.xiaomi.mipicks"
"com.xiaomi.miplay_client"
"com.xiaomi.mircs"
"com.xiaomi.mirror"
"com.xiaomi.payment"
"com.xiaomi.shop2"
"com.xiaomi.shop"
"com.xiaomi.simactivate.service"
"com.xiaomi.xmsfkeeper"
"com.xtsapp.coolvideo"
"com.xui.xhide"
"com.zaz.translate"
"cootek.smartinputv5.language.oem.hindi"
"flipboard.boxer.app"
"mobeam.barcodeservice"
"net.bat.store"
"ru.yandex.searchplugin"
"sec.android.app.dexonpc"
"sec.android.app.popupcalculator"
"sec.android.app.sbrowser"
"sec.android.app.voicenote"
"sec.android.daemonapp"
"sec.android.easymover.agent"
"sec.android.easyonehand"
"sec.android.mimage.avatarstickers"
"sec.android.splitsound"
"sg.bigo.live"
"tech.palm.id"
) do (
adb shell pm uninstall %%X
adb shell pm uninstall --user 0 %%X
)
taskkill /f /im adb.exe
pause
::play store ==> "com.android.vending"
::play store service ==> "com.google.android.gms"
::gboard ==> "com.google.android.inputmethod.latin"
::google login service ==> "com.google.android.gsf.login"
