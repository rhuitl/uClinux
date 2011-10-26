#TRUSTED 8b6456c10e9f0c99156cc6da971507d568eecf7b3b2587cbaba5afe9d847aa5df368630c12512d69e9d8cf1525fecee700c57cbb38d6ba42f3d8b4dbd1f5ffdebe73dc9823718b927ad233e6cad601fc271db0cede168f11976b80e4985a9dab377c0df489c381dd9f2b5e5bcd63732c49eeab6efa57fa3b054134538604bd230b2620f55f1db03ac4cd02d491fe6653e309add73173e3eb503586aa327be819405d6b4f27bab407c09b3b59a83593f6bf713141afdc1d7835b675371689812f4a59500d5972c561ddfcff833a7e932e3ed318506dd85caac0df2c08ffa4b32749b9a0a76bbdd916251cf50c5cb794151f4e2428b233124320edf2c04f58ac287497264e9bbe44e47715eeae77f61167b134cd9e7eb9a0c05557608d0919935d28381eb26f3304f9bb35b190b55684a626c8fdac493eec3940d55474da148dc9afe302955b117fa96ed29c20f23fbb4d72567dbadaa448f1aef0d8eaecdb42d66007bb27567b5cc45a63d730db1488a32dc48741c230f38f9062b09c8ae80744d5cc12ee7b198b7f9b8916ea1c80f63792993612565c6777002e8abcabfb63b6d66304a4c8cdf40998fa73f393f685584f636a29e8979a2e8b78c53777c7f02ae49243e332bc4e05cd5884faa279b3988d60664b04f6bb2e88bc6ce719987ba5a1ebdad9846c5ff22d132808855bd96e030eae13d511f6e011e862c8ed8b0913
#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22418);
 script_version ("1.0");
 script_bugtraq_id(20144);
 script_cve_id("CVE-2006-3507", "CVE-2006-3508", "CVE-2006-3509");
 
 name["english"] = "AirPort Update 2006-001 / Security Update 2006-005";
 

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the AirPort 
Wireless card.

Description :

The remote host is missing a security update regarding the drivers of 
the AirPort wireless card.

An attacker in the proximity of the target host may exploit this flaw 
by sending malformed 802.11 frames to the remote host and cause a stack 
overflow resulting in a crash of arbitrary code execution.

Solution : 

Apple has released a patch for this issue :
http://docs.info.apple.com/article.html?artnum=304420

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:L/AC:L/Au:NR/C:C/I:C/A:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of the Airport drivers";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

function vulnerable()
{
 security_warning( port : 0 );
 exit(0);
}
 


uname = get_kb_item("Host/uname");
if ( "Darwin" >!< uname ) exit(0);

if ( islocalhost() )
 info_t = INFO_LOCAL;
else
 {
  info_t = INFO_SSH;
  soc_g = ssh_login_or_reuse_connection();
  if ( ! soc_g ) exit(0);
 }


#
# Mac OS X < 10.4.7 is affected
#
if ( uname =~ "Version 8\.[0-6]\." ) vulnerable();

#
# Mac OS X < 10.3.9 is affected
# 
if ( uname =~ "Version 7\.[0-8]\." ) vulnerable();



get_build   = "system_profiler SPSoftwareDataType";
has_airport = "system_profiler SPAirPortDataType";
atheros = 'cd /System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/ && osascript -e \'tell application "Finder" to get {version} of alias "::AirPortAtheros5424.kext"\' | awk \'{print $1}\'';
 broadcom = 'cd /System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/ &&  osascript -e \'tell application "Finder" to get {version} of alias "::AppleAirPortBrcm4311.kext"\' | awk \'{print $1}\'';


  
build = info_send_cmd(cmd:get_build);
airport = info_send_cmd(cmd:has_airport);
if ( "Wireless Card Type: AirPort" >!< airport ) exit(0);  # No airport card installed

#
# AirPort Update 2006-001
#	-> Mac OS X 10.4.7 Build 8J2135 and 8J2135a
#
if ( egrep(pattern:"System Version: Mac OS X 10\.4\.7 \(8J2135a?", string:build) )
{
 atheros_version = info_send_cmd(cmd:atheros);
 broadcom_version = info_send_cmd(cmd:broadcom);
 if ( atheros_version =~ "^1\." )
	{
	 v = split(atheros_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 1 && int(v[1]) == 0 && int(v[2]) < 5 ) vulnerable();
	}
 if ( broadcom =~ "^1\." )
	{
	 v = split(broadcom_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 1 && int(v[1]) == 0 && int(v[2]) < 4 ) vulnerable();
	}
}
#
# Mac OS X Security Update 2006-005 (Tiger)
#	-> Mac OS X 10.4.7 build 8J135
#	-> Mac OS X 10.3.9 build 7W98
#
else if ( egrep(pattern:"System Version: Mac OS X 10\.4\.7 \(8J135", string:build) ||
          egrep(pattern:"System Version: Mac OS X 10\.3\.9 ", string:build) )
{
  cmd = "cd /System/Library/Extensions/AppleAirPort2.kext/Contents/ && grep -A 1 CFBundleGetInfoString /System/Library/Extensions/AppleAirPort2.kext/Contents/Info.plist | tail -n 1 | sed 's/<string>//g'|awk '{print $1}'";
  airport_version = info_send_cmd(cmd:cmd);
  if ( airport_version =~ "^4\. " )
  {
	 v = split(atheros_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 4 && int(v[1]) == 0 && int(v[2]) < 5 ) vulnerable();
  }
}


if ( ! localhost ) ssh_close_connection();
