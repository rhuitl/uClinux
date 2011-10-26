#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

 desc["english"] = "
Synopsis :

It is possible to enumerate remote services.

Description :

This plugin implements the SvcOpenSCManager() and SvcEnumServices()
calls to obtain, using the SMB protocol, the list of active services
of the remote host.

An attacker may use this feature to gain better knowledge of the remote
host.

Solution : 

To prevent the listing of the services for being obtained, you should
either have tight login restrictions, so that only trusted users can 
access your host, and/or you should filter incoming traffic to this port.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:N)";


if(description)
{
 script_id(10456);
 script_version ("$Revision: 1.28 $");
 
 name["english"] = "SMB enum services";
 
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Enumerates the list of remote services";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", 
 		     "SMB/login", 
		     "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");


port = kb_smb_transport();
if(!port)port = 139;


# Does not work against Samba
smb = get_kb_item("SMB/samba");
if(smb)exit(0);


name = kb_smb_name();
if(!name)return(FALSE);

if(!get_port_state(port))return(FALSE);

login = kb_smb_login();
pass  = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";

dom = kb_smb_domain();

	  
soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init (socket:soc,hostname:name);
ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1)
{
 close (soc);
 exit (0);
}


handle = OpenSCManager (access_mode:SC_MANAGER_ENUMERATE_SERVICE);
if (isnull (handle))
{
 NetUseDel();
 exit (0);
}

list = EnumServicesStatus (handle:handle, type:SERVICE_WIN32, state:SERVICE_ACTIVE);

CloseServiceHandle (handle:handle);
NetUseDel ();

if (isnull (list))
  exit (1);

services = NULL;

foreach elem (list)
{
 parse = GetService (service:elem);
 services += parse[1] + " [ " + parse[0] + ' ] \n';
}


if(services)
{
 set_kb_item(name:"SMB/svcs", value:services);

 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		services);

 security_note(data:report, port:port);
}
