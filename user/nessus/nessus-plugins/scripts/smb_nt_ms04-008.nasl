#
# Copyright (C) 2004 Tenable Network Security
#

if(description)
{
 script_id(12090);
 script_bugtraq_id(9825);
 #script_cve_id();

 script_version("$Revision: 1.6 $");

 name["english"] = "Windows Media Services Remote Denial of Service";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

It is possible to crash the remote Media Service.

Description :

The remote host appears to be vulnerable to a remote
Denial of Service Attack (DoS) against the Media Services
component.  An attacker, in exploiting this bug, would
render the Media Services component as unresponsive.

Solution : 

Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms04-008.mspx

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:A)";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for MS04-008";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("netbios_name_get.nasl",
                     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
                     "SMB/domain","SMB/transport");

 script_require_ports(139, 445);
 exit(0);
}

# start script

# let's try it without registry access first....
# reply packet on 1755 gives away version num like so:
# 03/10-00:01:01.143211 10.10.10.18:1755 -> 10.10.10.254:53311
# TCP TTL:128 TOS:0x0 ID:45786 IpLen:20 DgmLen:180 DF
# ***AP*** Seq: 0x8DDEA47  Ack: 0xE445AD47  Win: 0x43C0  TcpLen: 32
# TCP Options (3) => NOP NOP TS: 54663 1032720260
# 01 00 00 00 CE FA 0B B0 70 00 00 00 4D 4D 53 20  ........p...MMS
# 0E 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
# 0C 00 00 00 01 00 04 00 00 00 00 00 F0 F0 F0 F0  ................
# 0B 00 04 00 1C 00 03 00 00 00 00 00 00 00 F0 3F  ...............?
# 01 00 00 00 01 00 00 00 00 80 00 00 00 00 A0 00  ................
# 0B 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
# 34 00 2E 00 31 00 2E 00 30 00 2E 00 33 00 39 00  4...1...0...3.9.
# 33 00 30 00 00 00 00 00 00 00 00 00 00 00 00 00  3.0.............

port = 1755;
if (get_port_state(port)) {
    packet1 = raw_string(
    0x01, 0x00, 0x00, 0x00, 0xce, 0xfa, 0x0b, 0xb0, 0xa0, 0x00, 0x00, 0x00,
    0x4d, 0x4d, 0x53, 0x20, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf8, 0x53, 0xe3, 0xa5, 0x9b, 0xc4, 0x00, 0x40, 0x12, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x03, 0x00, 0xf0, 0xf0, 0xf0, 0xf0, 0x0b, 0x00, 0x04, 0x00,
    0x1c, 0x00, 0x03, 0x00, 0x4e, 0x00, 0x53, 0x00, 0x50, 0x00, 0x6c, 0x00,
    0x61, 0x00, 0x79, 0x00, 0x65, 0x00, 0x72, 0x00, 0x2f, 0x00, 0x34, 0x00,
    0x2e, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x33, 0x00,
    0x38, 0x00, 0x35, 0x00, 0x37, 0x00, 0x3b, 0x00, 0x20, 0x00, 0x7b, 0x00,
    0x30, 0x00, 0x32, 0x00, 0x64, 0x00, 0x30, 0x00, 0x63, 0x00, 0x32, 0x00,
    0x63, 0x00, 0x30, 0x00, 0x2d, 0x00, 0x62, 0x00, 0x35, 0x00, 0x30, 0x00,
    0x37, 0x00, 0x2d, 0x00, 0x31, 0x00, 0x31, 0x00, 0x64, 0x00, 0x32, 0x00,
    0x2d, 0x00, 0x39, 0x00, 0x61, 0x00, 0x61, 0x00, 0x38, 0x00, 0x2d, 0x00,
    0x62, 0x00, 0x37, 0x00, 0x30, 0x00, 0x66, 0x00, 0x33, 0x00, 0x30, 0x00,
    0x34, 0x00, 0x34, 0x00, 0x61, 0x00, 0x65, 0x00, 0x37, 0x00, 0x65, 0x00,
    0x7d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

    soc = open_sock_tcp(port);
    if (soc) {
        send(socket:soc, data:packet1);
        r=recv(socket:soc,length:65535, timeout:3);
        if (strlen(r) == 128) {
            if ( (r[96] == "4") && (r[100] == "1") && (r[104] == "0") ) {
                final = (int(r[108]) * 1000) + (int(r[110]) * 100) + (int(r[112]) * 10) + int(r[114]);
                if (final < 3930) security_warning(port); 
            }
        }
        close (soc);
        exit(0);
    }
}

# OK, if we made it this far, then port 1755 was not open and we'll check via the
# registry

include("smb_func.inc");
include("smb_hotfixes.inc");

if ( hotfix_check_sp(win2k:5) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB823353") <= 0 ) exit(0);


version = get_kb_item("SMB/WindowsVersion");
if ( ! version ) exit(0);


# only windows 2000 is vulnerable to this attack
if("5.0" >< version) {

 name	= kb_smb_name(); 	if(!name)exit(0);
 login	= kb_smb_login(); 
 pass	= kb_smb_password(); 	
 domain = kb_smb_domain(); 	
 port	= kb_smb_transport();

 if ( ! get_port_state(port) ) exit(0);
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);

 session_init(socket:soc, hostname:name);
 r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
 if ( r != 1 ) exit(0);

 hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
 if ( isnull(hklm) ) 
 {
  NetUseDel();
  exit(0);
 }

 key = "SOFTWARE\Microsoft\Updates\Windows Media Services\wm822343\";
 item = "ServerVersion";
 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if ( ! isnull(key_h) )
 {
  value = RegQueryValue(handle:key_h, item:item);
  if (!isnull (value) && (value[1] >< "4.1"))
  {
   key = "SOFTWARE\Microsoft\Updates\Windows Media Services\wm822343\FileList\File1";
   item = "Version";
   sp = get_kb_item("SMB/Win2K/ServicePack");

   # only service packs 2 thru 4 are vulnerable
   if( ereg(string:sp, pattern:"Service Pack [2-4]"))
   {
    key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if ( ! isnull(key_h) )
    {
     value = RegQueryValue(handle:key_h2, item:item);
     if (!isnull (value))
     {
      vers = split(value[1], sep:".");
      if ( (int(vers[0]) == 4) && (int(vers[1]) == 1) && (int(vers[2]) == 0) && (int(vers[3]) < 3932) )
          security_warning(port);
     }
  
     RegCloseKey(handle:key_h2);
    }
   }
  }

  RegCloseKey (handle:key_h); 
 }

 RegCloseKey (handle:hklm);
 NetUseDel();
}
