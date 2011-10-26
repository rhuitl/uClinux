# This script was written by William Craig
#

if(description)
{
 script_id(12244);
 script_cve_id("CVE-2004-0651");
 script_bugtraq_id(10301);
 script_version("$Revision: 1.6 $");

 name["english"] = " Sun Java Runtime Environment DoS ";
 script_name(english:name["english"]);

 desc["english"] = "
 The remote Windows machine is running a Java SDK or JRE version
 1.4.2_03 and prior which is vulnerable to a DoS attack.

 Solution: Upgrade to SDK and JRE 1.4.2_04
           http://java.sun.com/j2se/

 Risk factor: High";

 script_description(english:desc["english"]);
 summary["english"] = "Checks for Java SDK and JRE versions prior to 1.4.2_04";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 Netteksecure Inc. ");
 family["english"]= "Windows";
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl","smb_login.nasl",
                      "smb_registry_full_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
                     "SMB/registry_full_access");
 script_require_ports(139, 445);
 exit(0);
}

# start script



include("smb_nt.inc");

port = get_kb_item("SMB/transport");
if(!port) port = 445;
#access = get_kb_item("SMB/registry_full_access");
#if(!access) exit(0);

x_name = kb_smb_name();
if(!x_name)exit(0);

_smb_port = kb_smb_transport();
if(!_smb_port)exit(0);

if(!get_port_state(_smb_port)) exit(0);
login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();

if(!login)login = "";
if(!pass) pass = "";

          
soc = open_sock_tcp(_smb_port);
if(!soc) exit(0);

#
# Request the session
# 
r = smb_session_request(soc:soc,  remote:x_name);

if(!r) { close(soc); exit(0); }

#
# Negociate the protocol
#
prot = smb_neg_prot(soc:soc);
if(!prot){ close(soc); exit(0); }


r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
if(!r){ close(soc); exit(0); }
uid = session_extract_uid(reply:r);

r = smb_tconx(soc:soc, name:x_name, uid:uid, share:"IPC$");
tid = tconx_extract_tid(reply:r);
if(!tid){ close(soc); exit(0); }


r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
if(!r){ close(soc); exit(0);}
pipe = smbntcreatex_extract_pipe(reply:r);



r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
if(!r){ close(soc); exit(0); }
handle = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);

key = "SOFTWARE\JavaSoft\Java Runtime Environment";

key_h = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:handle);
if ( key_h )
{
 # Is the remote machine using the JRE?
 item= "CurrentVersion";
 data = registry_get_item_sz(soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:key_h);
 value = registry_decode_sz(data:data);
}

if ( value && ("1.4" >< value) )
{
  entries = registry_enum_key(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:key_h);

  foreach entry (entries)
  {
   if ( ereg(pattern:"^1\.4\.([01]|2_0[0-3])", string:entry) ) 
	  {
	   security_hole ( port:port );
	   exit(0);
	  }
  }
}


key = "SOFTWARE\JavaSoft\Java Development Kit";

key_h = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:handle);
if ( key_h )
{
 # Is the remote machine using the JRE?
 item= "CurrentVersion";
 data = registry_get_item_sz(soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:key_h);
 value = registry_decode_sz(data:data);
}

if ( value && ("1.4" >< value) )
{
  entries = registry_enum_key(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:key_h);

  foreach entry (entries)
  {
   if ( ereg(pattern:"^1\.4\.([01]|2_0[0-3])", string:entry) ) 
	  {
	   security_hole ( port:port );
	   exit(0);
	  }
  }
}

