#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

It is possible to access a network share.

Description :

The remote has one or many Windows shares that can be accessed
through the Network with the given credentials.
Depending on the share rights, it may allow an attacker to 
read/write confidential data.

Solution :

To restrict access under Windows, open the explorer, do a right
click on each shares, go to the 'sharing' tab, and click on 
'permissions'

Risk factor :

None";


 desc_hole["english"] = "
Synopsis :

It is possible to access a network share.

Description :

The remote has one or many Windows shares that can be accessed
through the Network.
Depending on the share rights, it may allow an attacker to 
read/write confidential data.

Solution :

To restrict access under Windows, open the explorer, do a right
click on each shares, go to the 'sharing' tab, and click on 
'permissions'

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(10396);
 script_bugtraq_id(8026);
 script_version ("$Revision: 1.56 $");
 script_cve_id("CVE-1999-0519", "CVE-1999-0520");
 name["english"] = "SMB shares access";
 
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Gets the list of remote accessible shares";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_enum_shares.nasl",
		     "smb_login_as_users.nasl", "smb_sid2user.nasl", 
		     "smb_sid2localuser.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");


function accessible_share (share)
{
 local_var ret, handle, readable, writeable, access, files;

 ret = NetUseAdd (share:share);
 if (ret == 1)
 {
  # Open current directory in read mode
  handle = CreateFile (file:"", desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_DIRECTORY,
                       share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
  if ( ! isnull (handle) )
  {
   readable = 1;
   CloseFile (handle:handle);
  }
  else
   readable = 0;

  # Open current directory in write mode
  handle = CreateFile (file:"", desired_access:GENERIC_WRITE, file_attributes:FILE_ATTRIBUTE_DIRECTORY,
                       share_mode:FILE_SHARE_READ | FILE_SHARE_WRITE, create_disposition:OPEN_EXISTING);
  if ( ! isnull (handle) )
  {
   writeable = 1;
   CloseFile (handle:handle);
  }
  else
   writeable = 0;

  # Access mode -> string
  access = " - (";
  if (readable == 1)
    access += "readable";
  if (writeable == 1)
  {
   if (readable == 1)
     access += ",";
    access += "writable";
  }
  access += ")";

  if (readable == 1)
  {
   files = NULL;

   handle = FindFirstFile (pattern:"\*");
   while (!isnull(handle) && (strlen (files) < 1000))
   {
    handle = FindNextFile (handle:handle);
    if (!isnull(handle))
      files += handle[1] + '\n';
   }
  }

  NetUseDel (close:FALSE);
  
  if ( ! isnull(files) )
    access += '\n  + Content of this share :\n' + files;
    
  return access;
 }

 return FALSE;
}


#
# Here we go
#		


port = kb_smb_transport();
if(!port) port = 139;

name = kb_smb_name();
if(!name)exit(0);

login = kb_smb_login();
pass =  kb_smb_password();

if(!login)login = "";
if(!pass)pass = "";

dom = kb_smb_domain();

if(!get_port_state(port))exit(0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:dom);
if ( r != 1 ) 
{
 exit(1);
}

count = 1;

shares = get_kb_list("SMB/shares");
if(isnull(shares))shares = make_list();

shares = make_list(shares);
addme = make_list();

foreach s (make_list("WINNT$", "C$", "D$", "ADMIN$", "ROOT"))
{
  flag = 0;
  foreach t (shares)
  {
    if ( t == s ) {
      	flag = 1;
	break;
    }
  }

  if ( flag == 0 ) addme = make_list(addme, s);
}


shares = make_list(shares, addme);


run = 1;


while(1)
{
vuln = "";
accs = "";


foreach share (shares) 
{
 if (share != "IPC$")
 {
  accs = accessible_share(share:share);
  if(accs)
  {
   vuln += string("- ", share, " ", accs, "\n");
  }
 }
}

NetUseDel ();

if(strlen(vuln) > 0)
 {
  kb_item = string("SMB/accessible_shares/", count);
  set_kb_item(name:kb_item, value:egrep(pattern:"^-", string:vuln));
  
  if(!strlen(login))t = "using a NULL session ";
  else t = string("as ", login);
  
  hole = 1;
  if ( login ) 
  {
   admin = get_kb_item("SMB/AdminName");
   local = get_kb_item("SMB/LocalAdminName");
   if ( (admin && admin >< login) || 
         (local && local >< login ) ||
         ("ADMIN$" >< vuln)) hole = 0;
  }

  rep = string("The following shares can be accessed ", t, " :\n\n")
   	+ vuln;

  if ( hole )
  {
   report = string (desc_hole["english"],
		"\n\nPlugin output :\n\n",
		rep);

   security_hole(port:port, data:report);
  }
  else
  {
   report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		rep);

   security_note(port:port, data:report);
  }
 }

if(get_kb_item("SMB/any_login"))exit(0);

a = string("SMB/ValidUsers/", count, "/Login");
b = string("SMB/ValidUsers/", count, "/Password");
login = string(get_kb_item(a));
pass  = string(get_kb_item(b));
count = count + 1;
if(!strlen(login) && !strlen(pass))exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:dom);
if ( r != 1 ) exit(1);
}
