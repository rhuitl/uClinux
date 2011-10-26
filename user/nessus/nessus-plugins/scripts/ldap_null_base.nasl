#
# This script was written by John Lampe (j_lampe@bellsouth.net)
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(10722);
  script_version ("$Revision: 1.12 $");
  script_name(english:"LDAP allows null bases");
  desc["english"] = "
Synopsis :

It is possible to disclose LDAP information.

Description :

Improperly configured LDAP servers will allow the directory BASE 
to be set to NULL.  This allows information to be culled without
any prior knowledge of the directory structure.  Coupled with a 
NULL BIND, an anonymous user can query your LDAP server using a 
tool such as 'LdapMiner'

Solution:

Disable NULL BASE queries on your LDAP server

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

  script_description(english:desc["english"]);
  script_summary(english:"Check for LDAP null base");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Remote file access");
  script_copyright(english:"By John Lampe....j_lampe@bellsouth.net");

  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}



#
# The script code starts here


string1 = raw_string (0x30,0x0C,0x02,0x01,0x01,0x60,0x07,0x02,0x01,0x02,0x04,0x00,0x80,0x80);
string2 = raw_string (0x30, 0x25, 0x02, 0x01, 0x02, 0x63, 0x20, 0x04, 0x00, 0x0A, 0x01, 0x00, 0x0A, 0x01, 0x00, 0x02,
                      0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0B, 0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74,
                      0x63, 0x6C, 0x61, 0x73, 0x73, 0x30, 0x00);
mystring = string(string1, string2);
positiveid = "supportedVersion";

port = get_kb_item("Services/ldap");
if (!port) port = 389;

if (get_port_state(port)) {
    soc = open_sock_tcp(port);
    if (!soc) {
        exit(0);
    }

    send(socket:soc, data:mystring);
    rez = recv(socket:soc, length:4096);
    l = strlen(rez);
    if (l >= 7)
    {
      error_code = substr(rez, l - 7, l - 5);
      if (hexstr(error_code) == "0a0100") security_note(port);
    }
}



