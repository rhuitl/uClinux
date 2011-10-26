#
# This script was written by John Lampe (j_lampe@bellsouth.net)
# See the Nessus Scripts License for details
#
if(description)
{
  script_id(10723);
  script_version ("$Revision: 1.18 $");

  script_cve_id("CVE-1999-0385");
  script_bugtraq_id(503);
  script_xref(name:"OSVDB", value:"9723");

  script_name(english:"LDAP allows anonymous binds");
  desc["english"] = "
Synopsis :

It is possible to disclose LDAP information.

Description :

Improperly configured LDAP servers will allow any user to connect to the
server and query for information.

Solution :

Disable NULL BIND on your LDAP server

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";



  script_description(english:desc["english"]);
  script_summary(english:"Check for LDAP null bind");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Remote file access");
  script_copyright(english:"By John Lampe....j_lampe@bellsouth.net");

  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}



#
# The script code starts here



function send_stuff (myport) {
    soc = open_sock_tcp(myport);
    if (!soc) {
        return(0);
    }
    send(socket:soc, data:string);
    rez = recv(socket:soc, length:4096);
    close(soc);
    return(rez);
}


port = get_kb_item("Services/ldap");
if (!port) port = 389;

string = raw_string (0x30,0x0C,0x02,0x01,0x01,0x60,0x07,0x02,0x01,0x02,0x04,0x00,0x80,0x80);
positiveid = raw_string (0x30,0x0C,0x02,0x01,0x01,0x61,0x07,0x0A,0x01,0x00,0x04,0x00,0x04,0x00);

if (get_port_state(port)) {
    result1 = send_stuff(myport:port);
    if(result1)
    {
    error_code = substr(result1, strlen(result1) - 7, strlen(result1) - 5);
    if (hexstr(error_code) == "0a0100") security_note(port);
    }
}





