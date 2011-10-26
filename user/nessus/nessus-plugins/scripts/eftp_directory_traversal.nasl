#
# This script was written by Michel Arboi <arboi@alussinan.org>
# starting from guild_ftp.nasl
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(10933);
  script_bugtraq_id(3333);
  script_cve_id("CVE-2001-1109");
  script_version("$Revision: 1.20 $");
 name["english"] = "EFTP tells if a given file exists";
 name["francais"] = "EFTP indique si un fichier existe";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote FTP server can be used to determine if a given
file exists on the remote host or not, by adding dot-dot-slashes
in front of them. 

For instance, it is possible to determine the presence
of \autoexec.bat by using the command SIZE or MDTM on
../../../../autoexec.bat

An attacker may use this flaw to gain more knowledge about
this host, such as its file layout. This flaw is specially
useful when used with other vulnerabilities.

Solution : update your EFTP server to 2.0.8.348 or change it
Risk factor : Low";
 


 desc["francais"] = "
Le serveur FTP distant peut être utilisé pour determiner
si un fichier donné existe ou non, en ajoutant des
../ devant son nom.

Par exemple, il est possible de determiner la présence
de \autoexec.bat en utilisant les commandes SIZE ou 
MDTM sur ../../../../autoexec.bat

Un pirate peut utiliser ce problème pour obtenir
plus d'informations sur ce système, comme la hiérarchie
de fichiers mise en place. Ce problème est d'autant plus
utile qu'il peut faciliter la mise en oeuvre de l'exploitation
d'autres vulnérabilités.

Solution : mettez votre serveur EFTP à jour en 2.0.8.348
ou changez-en
Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "EFTP directory traversal";
 summary["francais"] = "EFTP directory traversal";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Michel Arboi",
		francais:"Ce script est Copyright (C) 2001 Michel Arboi");
 family["english"] = "FTP";
 family["francais"] = "FTP";

 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/login");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
include("ftp_func.inc");
include('global_settings.inc');
if ( ! thorough_tests ) exit(0);

cmd[0] = "SIZE";
cmd[1] = "MDTM";

port = get_kb_item("Services/ftp");
if(!port)port = 21;
login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");
# login = "ftp"; pass = "test@test.com";

if(get_port_state(port))
{
 vuln=0; tested=0;
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(login)
  {
   if(ftp_authenticate(socket:soc, user:login, pass:pass))
   {
    tested=tested+1;
    for (i = 0; cmd[i]; i = i + 1)
    {
     req = string(cmd[i], " ../../../../../../autoexec.bat\r\n");
     send(socket:soc, data:req);
     r = ftp_recv_line(socket:soc);
     if("230 " >< r) vuln=vuln+1;
    }
   }
   else
   {
    # We could not log in ou could not download autoexec.
    # We'll just attempt to grab the banner and check for version
    # <= 2.0.7
    # I suppose that any version < 2 is vulnerable...
    r = ftp_recv_line(socket:soc);
    if(egrep(string:r, pattern:".*EFTP version ([01]|2\.0\.[0-7])\..*"))
     vuln = 1;
   }
  }
  close(soc);
  if (vuln)
  {
   if (tested)
   {
    security_warning(port);
   }
   else
   {
    rep="The remote FTP server may be used to determine if a given
file exists on the remote host or not, by adding dot-dot-slashes
in front of them. 

For instance, it should be possible to determine the presence
of \autoexec.bat by using the command SIZE or MDTM on
../../../../autoexec.bat

An attacker may use this flaw to gain more knowledge about
this host, such as its file layout. This flaw is specially
useful when used with other vulnerabilities.

*** Nessus could not test the presence of autoexec.bat
*** and solely relied on the version number of your
*** server, so this may be a false positive.

Solution : update your FTP server and change it
Risk factor : Low";
    security_warning(port:port, data:rep);
   }
   exit(0);
  }
 }
}

#
# NB: This server is also vulnerable to another attack.
#
# Date:  Thu, 13 Dec 2001 12:59:43 +0200
# From: "Ertan Kurt" <ertank@olympos.org>
# Affiliation: Olympos Security
# To: bugtraq@securityfocus.com
# Subject: EFTP 2.0.8.346 directory content disclosure
#
# It is possible to see the contents of every drive and directory of
# vulnerable server.
# A valid user account is required to exploit this vulnerability.
# It works both with encryption and w/o encryption.
# Here's how it's done:
# the user is logged in to his home directory (let's say d:\userdir)
# when the user issues a CWD to another directory server returns
# permission denied.
# But, first changing directory to "..." (it will chdir to d:\userdir\...)
# then issuing a CWD to "\" will say permission denied but it will
# successfully change to root directory of the current drive.
# And everytime we want to see a dir's content, we first CWD to our
# home directory and then CWD ...  and then CWD directly to desired
# directory (CWD c:/ or c:/winnt etc)
# 
# So it is possible to see directory contents but i did not test to see
# if there is a possible way to get/put files.
#
