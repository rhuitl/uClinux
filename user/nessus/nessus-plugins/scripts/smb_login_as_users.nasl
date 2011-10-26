#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(10404);
 script_version ("$Revision: 1.34 $");
 script_cve_id("CVE-1999-0504", "CVE-1999-0506");
 name["english"] = "SMB log in as users";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This script attempts to log into the remote host
using several login/password combinations.

It may be dangerous due to the fact that it may
lock accounts out if your security policy is ultra-tight.

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to log into the remote host";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "smb_sid2user.nasl",
		     "smb_sid2localuser.nasl",
 		     "snmp_lanman_users.nasl");
 script_require_keys("SMB/name");
 script_require_ports(139, 445);
 script_timeout(0);
 exit(0);
}

include("smb_func.inc");

if(get_kb_item("SMB/any_login"))exit(0);

if ( safe_checks() ) exit(0);


function log_in(login, pass, domain)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);

 session_init(socket:soc, hostname:kb_smb_name());
 r = NetUseAdd(login:login, password:pass, domain:domain);
 if ( r == 1 && session_is_guest() ) r = 0; 
 NetUseDel();

 if (r == 1)
   return TRUE;

 return(FALSE);
}


#----------------------------------------------------------------#
# 			  main()                                 #
#----------------------------------------------------------------#		

port = kb_smb_transport(); 
if(!get_port_state(port))exit(0);

finished = 0;
count = 1;
vuln = "";

okcount = 1;
login = kb_smb_login();
pass  = kb_smb_password();
dom = kb_smb_domain();

if ( login ) set_kb_item(name:string("SMB/ValidUsers/0/Login"), value:login);
if ( pass ) set_kb_item(name:string("SMB/ValidUsers/0/Password"), value:pass);

current = "SMB/Users";

if(log_in(login:"nessus"+rand(), pass:"nessus"+rand(), domain:dom))exit(0);


while(!finished)
{
 login = string(get_kb_item(string(current, count)));
 if(!login){
  	if(current == "SMB/LocalUsers/") 
	  {
   		finished = 1;
	  }
	else {
	  current = "SMB/LocalUsers/";
	  count = 0;
	}
 }
 else
 {
  if(log_in(login:login, pass:"", domain:dom))
  {
   vuln = vuln + string(". User '", login, "' has NO password !\n");
   a = string("SMB/ValidUsers/", okcount, "/Login");
   b = string("SMB/ValidUsers/", okcount, "/Password");
   if ( login ) set_kb_item(name:a, value:login);
   #set_kb_item(name:b, value:"");
   okcount = okcount + 1;
  }
  else if(log_in(login:login, pass:login, domain:dom))
  {
   vuln = vuln + string(". The password of '", login, "' is '", login, "' !\n");
   a = string("SMB/ValidUsers/", okcount, "/Login");
   b = string("SMB/ValidUsers/", okcount, "/Password");
   if ( login )
   {
    set_kb_item(name:a, value:login);
    set_kb_item(name:b, value:login);
   }
   okcount = okcount + 1;
  }
 }
 count = count + 1;
}

if(strlen(vuln))
{
 security_warning(port:port, data:vuln);
}
