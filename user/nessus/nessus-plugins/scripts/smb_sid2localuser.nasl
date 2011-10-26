#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

 desc["english"] = "
Synopsis :

It is possible to enumerate local users.

Description :

Using the host SID, it is possible to enumerates the local 
users on the remote Windows system. (we only enumerated users 
name whose ID is between 1000 and 2000 or whatever preferences
you set).

Risk factor : 

None";


if(description)
{
 script_id(10860);
 script_bugtraq_id(959);
 script_cve_id("CVE-2000-1200");
 script_version ("$Revision: 1.31 $");
 
 name["english"] = "SMB use host SID to enumerate local users";
 
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Enumerates users";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl",
		     "smb_host2sid.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/host_sid");
 script_require_ports(139, 445);
 script_add_preference(name:"Start UID : ", type:"entry", value:"1000");
 script_add_preference(name:"End UID : ", type:"entry", value:"1200");
 
 exit(0);
}


include("smb_func.inc");


#---------------------------------------------------------#
# call LsaLookupSid with only one sid			  #
#---------------------------------------------------------#

function get_name (handle, sid, rid)
{
 local_var fsid, psid, name, type, user, names, tmp;

 if ( isnull(sid[1]) )
	return NULL;

 fsid = sid[0] + raw_byte (b: ord(sid[1])+1) + substr(sid,2,strlen(sid)-1) + raw_dword (d:rid);

 psid = NULL;
 psid[0] = fsid;

 names = LsaLookupSid (handle:handle, sid_array:psid);
 if (isnull(names))
   return NULL;

 name = names[0];
 tmp = parse_lsalookupsid (data:name);
 type = tmp[0];
 user = tmp[2];

 return user;
}


port = kb_smb_transport();
if(!port)port = 139;
if(!get_port_state(port))exit(0);
__start_uid = script_get_preference("Start UID : ");
__end_uid   = script_get_preference("End UID : ");

if(__end_uid < __start_uid)
{
 t  = __end_uid;
 __end_uid = __start_uid;
 __start_uid = t;
}

if(!__start_uid)__start_uid = 1000;
if(!__end_uid)__end_uid = __start_uid + 200;

__no_enum = string(get_kb_item("SMB/LocalUsers/0"));
if(__no_enum)exit(0);

__no_enum = string(get_kb_item("SMB/LocalUsers/1"));
if(__no_enum)exit(0);


# we need the  netbios name of the host
name = kb_smb_name();
if(!name)exit(0);

login = kb_smb_login();
pass  = kb_smb_password();
if(!login)login = "";
if(!pass)pass = "";

domain = kb_smb_domain(); 


# we need the SID of the domain
sid = get_kb_item("SMB/host_sid");
if(!sid)exit(0);

sid = hex2raw2 (s:sid);

soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init (socket:soc,hostname:name);
ret = NetUseAdd (login:login, password:pass, domain:domain, share:"IPC$");
if (ret != 1)
{
 close (soc);
 exit (0);
}

handle = LsaOpenPolicy (desired_access:0x20801);
if (isnull(handle))
{
  NetUseDel ();
  exit (0);
}

num_users = 0;
set_kb_item(name:"SMB/LocalUsers/enumerated", value:TRUE);

n = get_name(handle:handle, sid:sid, rid:500);
if(n)
 {
 num_users = num_users + 1;
 report = report + string("- Administrator account name : ", n, " (id 500)\n");
 set_kb_item(name:string("SMB/LocalUsers/", num_users), value:n);
 set_kb_item(name:"SMB/LocalAdminName", value:n);
 }


n = get_name(handle:handle, sid:sid, rid:501);
if(n)
 {
  report = report + string("- Guest account name : ", n, " (id 501)\n");
  num_users = num_users + 1;
  set_kb_item(name:string("SMB/LocalUsers/", num_users), value:n);
 }

#
# Retrieve the name of the users between __start_uid and __start_uid
#
mycounter = __start_uid;
while(1)
{
 n = get_name(handle:handle, sid:sid, rid:mycounter);
 if(n)
 {
  report = report + string("- ", n, " (id ", mycounter, ")\n");
  num_users = num_users + 1;
  set_kb_item(name:string("SMB/LocalUsers/", num_users), value:n);
 }
 else if(mycounter > __end_uid)break;
 
 if(mycounter > (5 * __end_uid))break;
 
 
 mycounter++;
}


LsaClose (handle:handle);
NetUseDel ();
	
if(num_users > 0)
{
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		report);

 security_note(data:report, port:port);
}
