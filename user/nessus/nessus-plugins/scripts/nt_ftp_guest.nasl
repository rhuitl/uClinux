#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10166);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-1999-0546");
 name["english"] = "Windows NT ftp 'guest' account";
 name["francais"] = "Accompte 'guest' FTP de WindowsNT";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "There is a 'guest' FTP account.
This is usually not a good thing, since very often,
this account will not run in a chrooted environement,
so an attacker will be very likely to use it
to break into this system.

Solution : disable this FTP account.

Risk factor : Medium";


 desc["francais"] = "Il y a un compte FTP 'guest'.
Ce n'est habituellement pas une bonne
chose, puisque de tels accomptes ne
seront pas en environnement chroot,
donc un pirate peut s'en servir pour
pénétrer dans ce système.

Solution : désactivez cet accompte.

Facteur de risque : Moyen";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for guest/guest";
 summary["francais"] = "Vérifie guest/guest";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl", "DDI_FTP_Any_User_Login.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

# it the server accepts any login/password, then
# no need to do this check
include('ftp_func.inc');

any = get_kb_item("ftp/wftp_login_problem");
if(any)exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(get_port_state(port))
{
 if(get_kb_item("ftp/" + port + "/AnyUser"))exit(0);

 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:"guest", pass:""))
  {
   login = get_kb_item("ftp/login");
   if(!login)
   {
    set_kb_item(name:"ftp/login", value:"guest");
    set_kb_item(name:"ftp/password", value:"guest");
   }
   security_warning(port);
  }
  close(soc);
 }
}
