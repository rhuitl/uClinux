#
# (C) Tenable Network Security
#
# This script is released under the GPLv2
#

if(description)
{
 script_id(11329);

 script_version("$Revision: 1.68 $");

 name["english"] = "The remote host is infected by a virus";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script checks for the presence of different virii on the remote
host, by using the SMB credentials you provide Nessus with.

- W32/Badtrans-B
- JS_GIGGER.A@mm
- W32/Vote-A
- W32/Vote-B
- CodeRed
- W32.Sircam.Worm@mm
- W32.HLLW.Fizzer@mm
- W32.Sobig.B@mm
- W32.Sobig.E@mm
- W32.Sobig.F@mm
- W32.Sobig.C@mm
- W32.Yaha.J@mm
- W32.mimail.a@mm
- W32.mimail.c@mm
- W32.mimail.e@mm
- W32.mimail.l@mm
- W32.mimail.p@mm
- W32.Welchia.Worm
- W32.Randex.Worm
- W32.Beagle.A
- W32.Novarg.A
- Vesser
- NetSky.C
- Doomran.a
- Beagle.m
- Beagle.j
- Agobot.FO
- NetSky.W
- Sasser
- W32.Wallon.A
- W32.MyDoom.M
- W32.MyDoom.AI
- W32.MyDoom.AX
- W32.Aimdes.B
- W32.Aimdes.C
- W32.ahker.D
- Hackarmy.i
- W32.Erkez.D/Zafi.d
- Winser-A
- Berbew.K
- Hotword.b
- W32.Backdoor.Ginwui.B
- W32.Wargbot
- W32.Randex.GEL
	
Risk factor : High
Solution : See the URLs which will appear in the report";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of different virii on the remote host";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",  "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
if ( get_kb_item("SMB/samba") ) exit(0);

global_var handle;

name = kb_smb_name();
if(!name)exit(0);

port = kb_smb_transport();
if(!port)exit(0);

if(!get_port_state(port))return(FALSE);
login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();

if(!login)login = "";
if(!pass) pass = "";

	  
soc = open_sock_tcp(port);
if(!soc) exit(0);

session_init(socket:soc, hostname:name);
ret = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( ret != 1 ) exit(0);
handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(handle) ) exit(0);

run = "SOFTWARE\Microsoft\Windows\CurrentVersion";
key_h = RegOpenKey(handle:handle, key:run, mode:MAXIMUM_ALLOWED);
n = 0;

if ( ! isnull(key_h) ) 
{
 info = RegQueryInfoKey(handle:key_h);
 if ( ! isnull(info) ) 
 {
  for ( i = 0 ; i != info[0] ; i ++ )
  {
   value = RegEnumValue(handle:key_h, index:i);
   if ( isnull(value) ) break;

   content = RegQueryValue(handle:key_h, item:value[1]);
   run_content[n++] = value[1];
   run_content[n++] = content[1];
  }
 }
}

RegCloseKey(handle:key_h);

function check_reg(name, url, key, item, exp)
{
  local_var key_h, sz, i, report;

  # Look in our local "cache" first
  if ( key == "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" )
  {
    for ( i = 0 ; run_content[i]; i += 2 )
	{
	  if ( run_content[i] == item )
		{
		 if ( exp == NULL ) return TRUE;
		 else if ( tolower(exp) >< tolower(run_content[i+1]) ) return TRUE;
		 else return FALSE;
		}
	} 
    return FALSE;
  }

  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if  ( ! isnull(key_h) )
  {
    value = RegQueryValue(handle:key_h, item:item);
    RegCloseKey(handle:key_h);
    if ( isnull(value) ) return 0;
  }
  else return 0;
  
 if(exp == NULL || tolower(exp) >< tolower(value))
 {
  report = string(
"The virus '", name, "' is present on the remote host\n",
"Solution : ", url, "\n",
"Risk factor : High");
 
  security_hole(port:kb_smb_transport(), data:report);
 }
}




i = 0;
name = NULL;

# http://www.infos3000.com/infosvirus/badtransb.htm
name[i] 	= "W32/Badtrans-B";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.badtrans.b@mm.html";
key[i] 		= "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
item[i] 	= "kernel32";
exp[i]		= "kernel32.exe";

i++;

# http://www.infos3000.com/infosvirus/jsgiggera.htm
name[i] 	= "JS_GIGGER.A@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/js.gigger.a@mm.html";
key[i] 		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i] 	= "NAV DefAlert";
exp[i]		= NULL;

i ++;

# http://www.infos3000.com/infosvirus/vote%20a.htm
name[i]		= "W32/Vote-A";
url[i]		= "http://www.sophos.com/virusinfo/analyses/w32vote-a.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "Norton.Thar";
exp[i]		= "zacker.vbs";

i++ ;

name[i]         = "W32/Vote-B";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.vote.b@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "ZaCker";
exp[i]          = "DaLaL.vbs";

i ++;

# http://www.infos3000.com/infosvirus/codered.htm
name[i]		= "CodeRed";
url[i]		= "http://www.symantec.com/avcenter/venc/data/codered.worm.html";
key[i]		= "SYSTEM\CurrentControlSet\Services\W3SVC\Parameters";
item[i]		= "VirtualRootsVC";
exp[i]		= "c:\,,217";

i ++;

# http://www.infos3000.com/infosvirus/w32sircam.htm
name[i]		= "W32.Sircam.Worm@mm";
url[i]		= "http://www.symantec.com/avcenter/venc/data/w32.sircam.worm@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[i]		= "Driver32";
exp[i] 		= "scam32.exe";

i++;

name[i]  	= "W32.HLLW.Fizzer@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.hllw.fizzer@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "SystemInit";
exp[i]		= "iservc.exe";

i++;

name[i]  	= "W32.Sobig.B@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.b@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "SystemTray";
exp[i]		= "msccn32.exe";

i ++;

name[i]		= "W32.Sobig.E@mm";
url[i]		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.e@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "SSK Service";
exp[i]		= "winssk32.exe";

i ++;

name[i]		= "W32.Sobig.F@mm";
url[i]		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.f@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "TrayX";
exp[i]		= "winppr32.exe";

i ++;

name[i]		= "W32.Sobig.C@mm";
url[i]		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.c@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "System MScvb";
exp[i]		= "mscvb32.exe";

i ++;

name[i] 	= "W32.Yaha.J@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.yaha.j@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "winreg";
exp[i]		= "winReg.exe";


i++;

name[i] 	= "W32.mimail.a@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.a@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "VideoDriver";
exp[i]		= "videodrv.exe";


i++;

name[i] 	= "W32.mimail.c@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.c@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "NetWatch32";
exp[i]		= "netwatch.exe";

i++;

name[i] 	= "W32.mimail.e@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.e@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "SystemLoad32";
exp[i]		= "sysload32.exe";

i++;
name[i] 	= "W32.mimail.l@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.l@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "France";
exp[i]		= "svchost.exe";

i++;
name[i] 	= "W32.mimail.p@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.p@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "WinMgr32";
exp[i]		= "winmgr32.exe";

i++;

name[i]        = "W32.Welchia.Worm";
url[i]         = "http://securityresponse.symantec.com/avcenter/venc/data/w32.welchia.worm.html";
key[i]         = "SYSTEM\CurrentControlSet\Services\RpcTftpd";
item[i]        = "ImagePath";
exp[i]         = "%System%\wins\svchost.exe";


i++;

name[i]        = "W32.Randex.Worm";
url[i]         = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.b.html";
key[i]         = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]        = "superslut";
exp[i]         = "msslut32.exe";

i++;

name[i]        = "W32.Randex.Worm";
url[i]         = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.c.html";
key[i]         = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]        = "Microsoft Netview";
exp[i]         = "gesfm32.exe";

i++;

name[i]        = "W32.Randex.Worm";
url[i]         = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.d.html";
key[i]         = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]        = "mssyslanhelper";
exp[i]         = "msmsgri32.exe";


i++;

name[i]        = "W32.Randex.Worm";
url[i]         = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.d.html";
key[i]         = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]        = "mslanhelper";
exp[i]         = "msmsgri32.exe";

i ++;
name[i]        = "W32.Beagle.A";
url[i]         = "http://securityresponse.symantec.com/avcenter/venc/data/w32.beagle.a@mm.html";
key[i]         = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]        = "d3update.exe";
exp[i]         = "bbeagle.exe";

i ++;

name[i]        = "W32.Novarg.A";
url[i]         = "http://securityresponse.symantec.com/avcenter/venc/data/w32.novarg.a@mm.html";
key[i]         = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]        = "TaskMon";
exp[i]         = "taskmon.exe";

i++;

name[i]       = "Vesser";
url[i]        = "http://www.f-secure.com/v-descs/vesser.shtml";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "KernelFaultChk";
exp[i]        = "sms.exe";

i++;

name[i]       = "NetSky.C";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.netsky.c@mm.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "ICQ Net";
exp[i]        = "winlogon.exe";


i++;

name[i]      = "Doomran.a";
url[i]       = "http://es.trendmicro-europe.com/enterprise/security_info/ve_detail.php?Vname=WORM_DOOMRAN.A";
key[i]       = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]      = "Antimydoom";
exp[i]       = "PACKAGE.EXE";

i++;

name[i]      = "Beagle.m";
url[i]       = "http://securityresponse.symantec.com/avcenter/venc/data/w32.beagle.m@mm.html";
key[i]       = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]      = "winupd.exe";
exp[i]       = "winupd.exe";

i++;

name[i]      = "Beagle.j";
url[i]       = "http://securityresponse.symantec.com/avcenter/venc/data/w32.beagle.j@mm.html";
key[i]       = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]      = "ssate.exe";
exp[i]       = "irun4.exe";

i++;

name[i]      = "Agobot.FO";
url[i]       = "http://www.f-secure.com/v-descs/agobot_fo.shtml";
key[i]       = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]      = "nVidia Chip4";
exp[i]       = "nvchip4.exe";

i ++;
name[i]       = "NetSky.W";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.netsky.w@mm.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "NetDy";
exp[i]        = "VisualGuard.exe";


i++;
name[i]       = "Sasser";
url[i]        = "http://www.lurhq.com/sasser.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "avserve.exe";
exp[i]        = "avserve.exe";

i++;
name[i]       = "Sasser.C";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.sasser.c.worm.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "avserve2.exe";
exp[i]        = "avserve2.exe";

i++;
name[i]       = "W32.Wallon.A";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.wallon.a@mm.html";
key[i]        = "SOFTWARE\Microsoft\Internet Explorer\Extensions\{FE5A1910-F121-11d2-BE9E-01C04A7936B1}";
item[i]       = "Icon";
exp[i]        = NULL;


i++;
name[i]       = "W32.MyDoom.M / W32.MyDoom.AX";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.mydoom.ax@mm.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "JavaVM";
exp[i]        = "JAVA.EXE";

i++;
name[i]       = "W32.MyDoom.AI";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.mydoom.ai@mm.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "lsass";
exp[i]        = "lsasrv.exe";

i++;
name[i]       = "W32.aimdes.b / W32.aimdes.c";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.aimdes.c@mm.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "MsVBdll";
exp[i]        = "sys32dll.exe";


i++;
name[i]       = "W32.ahker.d";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.ahker.d@mm.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "Norton Auto-Protect";
exp[i]        = "ccApp.exe";

i++;
name[i]       = "Trojan.Ascetic.C";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/trojan.ascetic.c.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "SystemBoot";
exp[i]        = "Help\services.exe";

i++;
name[i]       = "W32.Alcra.A";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.alcra.a.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "p2pnetwork";
exp[i]        = "p2pnetwork.exe";

i++;
name[i]       = "W32.Shelp";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.shelp.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "explorer";
exp[i]        = "explorer.exe";


# Submitted by David Maciejak
i++;
name[i]       = "Winser-A";
url[i]        = "http://www.sophos.com/virusinfo/analyses/trojwinsera.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "nortonsantivirus";
exp[i]        = NULL;

i++;
name[i]         = "Backdoor.Berbew.O";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/backdoor.berbew.o.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad";
item[i]         = "Web Event Logger";
exp[i]          = "{7CFBACFF-EE01-1231-ABDD-416592E5D639}";

i++;
name[i]         = "w32.beagle.az";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.beagle.az@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "Sysformat";
exp[i]          = "sysformat.exe";

i++;
name[i]       = "Hackarmy.i";
url[i]        = "http://www.zone-h.org/en/news/read/id=4404/";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "putil";
exp[i]        = "%windir%";


i++;
name[i]       = "W32.Assiral@mm";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.assiral@mm.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "MS_LARISSA";
exp[i]        = "MS_LARISSA.exe";

i++;
name[i]       = "Backdoor.Netshadow";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/backdoor.netshadow.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "Windows Logger";
exp[i]        = "winlog.exe";

i++;
name[i]       = "W32.Ahker.E@mm";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.ahker.e@mm.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "Generic Host Process for Win32 Services";
exp[i]        = "bazzi.exe";

i++;
name[i]       = "W32.Bropia.R";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.bropia.r.html";
key[i]        = "Microsoft\Windows\CurrentVersion\Run";
item[i]       = "Wins32 Online";
exp[i]        = "cfgpwnz.exe";

i++;
name[i]       = "Trojan.Prevert";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/trojan.prevert.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "Service Controller";
exp[i]        = "%System%\service.exe";

i++;
name[i]       = "W32.AllocUp.A";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.allocup.a.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = ".msfupdate";
exp[i]        = "%System%\msveup.exe";

i++;
name[i]       = "W32.Kelvir.M";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.kelvir.m.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "LSASS32";
exp[i]        = "Isass32.exe";

i++;
name[i]       = "VBS.Ypsan.B@mm";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/vbs.ypsan.b@mm.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "BootsCfg";
exp[i]        = "wscript.exe C:\WINDOWS\System\Back ups\Bkupinstall.vbs";

i++;
name[i]       = "W32.Mytob.AA@mm";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.mytob.aa@mm.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "MSN MESSENGER";
exp[i]        = "msnmsgs.exe";

i++;
name[i]       = "Dialer.Asdplug";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/dialer.asdplug.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "ASDPLUGIN";
exp[i]        = "exe -N";



# Submitted by Jeff Adams
i++;
name[i]       = "W32.Erkez.D/Zafi.D";
url[i]        = "http://securityresponse.symantec.com/avcenter/venc/data/w32.erkez.d@mm.html";
key[i]        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]       = "Wxp4";
exp[i]        = "Norton Update";

i ++;

name[i]         = "W32.blackmal.e@mm (CME-24)";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.blackmal.e@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "ScanRegistry";
exp[i]          = "scanregw.exe";

i ++;

name[i]         = "W32.Randex.GEL";
url[i]          = "http://www.symantec.com/security_response/writeup.jsp?docid=2006-081910-4849-99&tabid=2";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[i]         = "MS Java for Windows XP & NT";
exp[i]          = "javanet.exe";

i ++;

name[i]         = "W32.Randex.GEL";
url[i]          = "http://www.symantec.com/security_response/writeup.jsp?docid=2006-081910-4849-99&tabid=2";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[i]         = "MS Java for Windows NT";
exp[i]          = "msjava.exe";

i ++;

name[i]         = "W32.Randex.GEL";
url[i]          = "http://www.symantec.com/security_response/writeup.jsp?docid=2006-081910-4849-99&tabid=2";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[i]         = "MS Java Applets for Windows NT, ME & XP";
exp[i]          = "japaapplets.exe";

i ++;

name[i]         = "W32.Randex.GEL";
url[i]          = "http://www.symantec.com/security_response/writeup.jsp?docid=2006-081910-4849-99&tabid=2";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[i]         = "Sun Java Console for Windows NT & XP";
exp[i]          = "jconsole.exe";

for(i=0;name[i];i++)
{
  check_reg(name:name[i], url:url[i], key:key[i], item:item[i], exp:exp[i]);
}




RegCloseKey(handle:handle);
NetUseDel(close:FALSE);

rootfile = hotfix_get_systemroot();
if ( ! rootfile ) exit(0);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\system.ini", string:rootfile);


r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(1);
}


handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 off = 0;
 resp = ReadFile(handle:handle, length:16384, offset:off);
 data = resp;
 while(strlen(resp) >= 16383)
 {
  off += strlen(resp);
  resp = ReadFile(handle:handle, length:16384, offset:off);
  data += resp;
  if(strlen(data) > 1024 * 1024)break;
 }


 CloseFile(handle:handle);


 if("shell=explorer.exe load.exe -dontrunold" >< data)
 {
  report = string(
"The virus 'W32.Nimda.A@mm' is present on the remote host\n",
"Solution : http://www.symantec.com/avcenter/venc/data/w32.nimda.a@mm.html\n",
"Risk factor : High");
 
  security_hole(port:port, data:report);
 }
}
 
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\goner.scr", string:rootfile); 

handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 report = string(
"The virus 'W32.Goner.A@mm' is present on the remote host\n",
"Solution : http://www.symantec.com/avcenter/venc/data/w32.goner.a@mm.html\n",
"Risk factor : High"); 
 security_hole(port:port, data:report);
 CloseFile(handle:handle);
}

file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\winxp.exe", string:rootfile); 

handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 report = string(
"The virus 'W32.Bable.AG@mm' is present on the remote host\n",
"Solution : http://www.symantec.com/avcenter/venc/data/w32.beagle.ag@mm.html\n",
"Risk factor : High"); 
 security_hole(port:port, data:report);
 CloseFile(handle:handle);
}


file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\System32\dnkkq.dll", string:rootfile); 

handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 report = string(
"The backdoor 'Backdoor.Berbew.K' is present on the remote host\n",
"Backdoor.Berbew.K is a backdoor which is designed to intercept the logins
and passwords used by the users of the remote host and send them to a 
third party. It usually saves the gathered data in :
	System32\dnkkq.dll
	System32\datakkq32.dll
	System32\kkq32.dll

Delete these files and make sure to disable IE's Autofill feature for important
data (ie: online banking, credit cart numbers, etc...)

Solution : http://securityresponse.symantec.com/avcenter/venc/data/backdoor.berbew.k.html
Risk factor : High"); 
 security_hole(port:port, data:report);
 CloseFile(handle:handle);
}


file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Swen1.dat", string:rootfile); 

handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 report = string(
"The virus 'W32.Swen.A@mm' is present on the remote host\n",
"Solution : http://securityresponse.symantec.com/avcenter/venc/data/w32.swen.a@mm.html\n",
"Risk factor : High"); 
 security_hole(port:port, data:report);
 CloseFile(handle:handle);
}


# Submitted by Josh Zlatin-Amishav

file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:rootfile); 
#trojanname = raw_string(0xFF, 0x73, 0x76, 0x63, 0x68, 0x6F, 0x73, 0x74, 0x2E, 0x65,0x78, 0x65);
trojanname = raw_string(0xa0, 0x73, 0x76, 0x63, 0x68, 0x6F, 0x73, 0x74, 0x2E, 0x65,0x78, 0x65);

handle = CreateFile (file:string(file, "\\System32\\",trojanname),
                     desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_HIDDEN,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( isnull(handle) )
handle = CreateFile (file:string(file, "\\System32\\_svchost.exe"),
                     desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( isnull(handle) )
  handle = CreateFile (file:string(file, "\\System32\\Outlook Express"),
                       desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                       share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( isnull(handle) )
handle = CreateFile (file:string(file, "\\System32\\CFXP.DRV"),
                     desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( isnull(handle) )
handle = CreateFile (file:string(file, "\\System32\\CHJO.DRV"),
                     desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( isnull(handle) )
handle = CreateFile (file:string(file, "\\System32\\MMSYSTEM.DLX"),
                     desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( isnull(handle) )
handle = CreateFile (file:string(file, "\\System32\\OLECLI.DLX"),
                     desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( isnull(handle) )
handle = CreateFile (file:string(file, "\\System32\\Windll.dlx"),
                     desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( isnull(handle) )
handle = CreateFile (file:string(file, "\\System32\\Activity.AVI"),
                     desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( isnull(handle) )
handle = CreateFile (file:string(file, "\\System32\\Upgrade.AVI"),
                     desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( isnull(handle) )
handle = CreateFile (file:string(file, "\\System32\\System.lst"),
                     desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( isnull(handle) )
handle = CreateFile (file:string(file, "\\System32\\PF30txt.dlx"),
                     desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if( ! isnull(handle) )
{
  report = string(
"The trojan 'hotword' is present on the remote host\n",
"See also : http://securityresponse.symantec.com/avcenter/venc/data/trojan.hotword.html\n",
"See also : http://securityresponse.symantec.com/avcenter/venc/data/trojan.rona.html\n",
"Solution :  Use latest anti-virus signatures to clean the machine.\n",
"Risk factor : High"); 
  security_hole(port:port, data:report);
}




# Submitted by David Maciejak

sober = make_list("nonzipsr.noz",
"clonzips.ssc",
"clsobern.isc",
"sb2run.dii",
"winsend32.dal",
"winroot64.dal",
"zippedsr.piz",
"winexerun.dal",
"winmprot.dal",
"dgssxy.yoi",
"cvqaikxt.apk",
"sysmms32.lla",
"Odin-Anon.Ger");

foreach f (sober)
{
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\" + f, string:rootfile); 
 handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                      share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
 if( ! isnull(handle) )
 {
  report = string(
"The virus 'Sober.i@mm' is present on the remote host\n",
"Solution : http://securityresponse.symantec.com/avcenter/venc/data/w32.sober.i@mm.html\n",
"Risk factor : High"); 
  security_hole(port:port, data:report);
  CloseFile(handle:handle);
 }
}

file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\System32\wgareg.exe", string:rootfile); 

handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 report = string(
"The virus 'W32.Wargbot@mm' is present on the remote host\n",
"Solution : http://www.symantec.com/security_response/writeup.jsp?docid=2006-081312-3302-99\n",
"Risk factor : High"); 
 security_hole(port:port, data:report);
 CloseFile(handle:handle);
}



# Submitted by Josh Zlatin-Amishav

foreach f (make_list("zsydll.dll", "zsyhide.dll"))
{
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\System32\" + f, string:rootfile);

 handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                      share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
 if( ! isnull(handle) )
 {
   report = string(
   "The backdoor 'W32.Backdoor.Ginwui.B' is present on the remote host\n",
   "See also : http://securityresponse.symantec.com/avcenter/venc/data/backdoor.ginwui.b.html\n",
   "Solution :  Use latest anti-virus signatures to clean the machine.\n",
   "Risk factor : High");
   security_hole(port:port, data:report);
   CloseFile(handle:handle);
 }
} 

NetUseDel();
