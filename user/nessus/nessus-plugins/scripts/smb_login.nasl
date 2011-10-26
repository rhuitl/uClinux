#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

It is possible to logon on the remote host.

Description :

The remote host is running one of the Microsoft Windows operating
system. It was possible to logon using one of the following
account :

- NULL session
- Guest account
- Given Credentials

See also :

http://support.microsoft.com/support/kb/articles/Q143/4/74.ASP
http://support.microsoft.com/support/kb/articles/Q246/2/61.ASP

Risk factor :

none";


 desc_hole["english"] = "
Synopsis :

It is possible to logon on the remote host.

Description :

The remote host is running one of the Microsoft Windows operating
system. It was possible to logon using the administrator account
with a blank password.

See Also :

http://support.microsoft.com/support/kb/articles/Q143/4/74.ASP
http://support.microsoft.com/support/kb/articles/Q246/2/61.ASP

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


if(description)
{
 script_id(10394);
 script_bugtraq_id(494, 990, 11199);
 script_version ("$Revision: 1.84 $");
 script_cve_id("CVE-1999-0504", "CVE-1999-0506", "CVE-2000-0222", "CVE-1999-0505", "CVE-2002-1117");
 name["english"] = "SMB log in";
 
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to log into the remote host";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "cifs445.nasl", "find_service.nes", "logins.nasl", "smb_nativelanman.nasl");
 if ( NASL_LEVEL >= 2202 ) script_dependencies("kerberos.nasl");
 script_require_keys("SMB/name", "SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");


function login(lg, pw, dom)
{ 
 local_var r, soc;

 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);

 session_init(socket:soc, hostname:name);
 r = NetUseAdd(login:lg, password:pw, domain:dom, share:"IPC$");
 NetUseDel();

 if ( r == 1 )
  return TRUE;
 else
  return FALSE;
}



login_has_been_supplied = 0;
port = kb_smb_transport();
name = kb_smb_name();

if ( ! get_port_state(port) )
  exit(0);

soc = open_sock_tcp(port);
if ( !soc )
  exit(0);

for ( i = 0 ; TRUE ; i ++ )
{
 l = get_kb_item("SMB/login_filled/" + i );
 if (l)
   l = ereg_replace(pattern:"([^ ]*) *$", string:l, replace:"\1");

 p = get_kb_item("SMB/password_filled/" + i );
 if (p)
   p = ereg_replace(pattern:"([^ ]*) *$", string:p, replace:"\1");
 else
   p = "";

 d = get_kb_item("SMB/domain_filled/" + i );
 if (d)
   d = ereg_replace(pattern:"([^ ]*) *$", string:d, replace:"\1");

 if ( l )
 {
  login_has_been_supplied ++;
  logins[i] = l;
  passwords[i] = p;
  domains[i] = d;
 }
 else break;
}

smb_domain = string(get_kb_item("SMB/workgroup"));

if (smb_domain)
{
 smb_domain = ereg_replace(pattern:"([^ ]*) *$", string:smb_domain, replace:"\1");
}

hole = 0;
rand_lg = string ( "nessus", rand(), rand(), rand() ); 
rand_pw = string ( "nessus", rand(), rand(), rand() );


valid_logins   = make_list();
valid_passwords = make_list();



if ( login(lg:NULL, pw:NULL, dom:NULL) == TRUE )
 null_session = TRUE;
else
 null_session = FALSE;

if ( ( login(lg:"administrator", pw:NULL, dom:NULL) == TRUE ) && ( session_is_guest() == 0 ) )
 admin_no_pw = TRUE;
else
 admin_no_pw = FALSE;

if ( ( login(lg:rand_lg, pw:rand_pw, dom:NULL) == TRUE ) )
{
 any_login = TRUE;
 set_kb_item(name:"SMB/any_login", value:TRUE);
}
else
 any_login = FALSE;

supplied_login_is_correct = FALSE;

for ( i = 0 ; logins[i] && supplied_login_is_correct == FALSE ; i ++ )
{
  user_login = logins[i];
  user_password = passwords[i];
  user_domain = domains[i];

 if ((login(lg:user_login, pw:user_password, dom:user_domain) == TRUE )  && ( session_is_guest() == 0 ))
 {
  supplied_login_is_correct = TRUE;
  smb_domain = user_domain;
 }
 else
 {
  if (tolower(user_domain) != tolower(smb_domain))
  {
   if ((login(lg:user_login, pw:user_password, dom:smb_domain) == TRUE )  && ( session_is_guest() == 0 ))
   {
    supplied_login_is_correct = TRUE;
   }
  }

  if (!supplied_login_is_correct)
  {
   if ((login(lg:user_login, pw:user_password, dom:NULL) == TRUE )  && ( session_is_guest() == 0 ))
   {
    supplied_login_is_correct = TRUE;
    smb_domain = NULL;
   }
  }

 }
}


if ( null_session || supplied_login_is_correct || admin_no_pw || any_login )
{
 if ( null_session != 0 )
  report = string("- NULL sessions are enabled on the remote host\n");

 if ( supplied_login_is_correct )
 {
  if ( ! user_password ) user_password = "";

  set_kb_item(name:"SMB/login", value:user_login);
  set_kb_item(name:"SMB/password", value:user_password);
  if ( smb_domain != NULL ) set_kb_item(name:"SMB/domain", value:smb_domain);
  report += string("- The SMB tests will be done as '", user_login, "'/'******'\n");
 }

 if ( admin_no_pw && !any_login)
 {
  report += string("- The 'administrator' account has no password set\n");
  hole = 1;
  if ( supplied_login_is_correct == FALSE )
  {
  set_kb_item(name:"SMB/login", value:"administrator");
  set_kb_item(name:"SMB/password", value:"");
  set_kb_item(name:"SMB/domain", value:"");
  }
 }

 if ( any_login )
 {
  report += string("- Remote users are authenticated as 'Guest'\n");
  if (( supplied_login_is_correct == FALSE ) && ( admin_no_pw == 0 ))
  {
  set_kb_item(name:"SMB/login", value:rand_lg);
  set_kb_item(name:"SMB/password", value:rand_pw);
  set_kb_item(name:"SMB/domain", value:"");
  }
 }

 if (null_session)
 {
  if (( supplied_login_is_correct == FALSE ) && ( admin_no_pw == 0 ) && ( any_login == FALSE ))
  {
  set_kb_item(name:"SMB/login", value:"");
  set_kb_item(name:"SMB/password", value:"");
  set_kb_item(name:"SMB/domain", value:"");
  }
 }


 if ( supplied_login_is_correct == FALSE && admin_no_pw == 0 && login_has_been_supplied != 0 )
  set_kb_item(name:"HostLevelChecks/smb/failed", value:TRUE);

 if ( supplied_login_is_correct || admin_no_pwd )
  set_kb_item(name:"Host/local_checks_enabled", value:TRUE);

 
 if ( hole )
 {
  report = string (desc_hole["english"],
		"\n\nPlugin output :\n\n",
		report);
  security_hole(port:port, data:report);
 }
 else
 {
  report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		report);
  security_note(port:port, data:report);
 }
}
