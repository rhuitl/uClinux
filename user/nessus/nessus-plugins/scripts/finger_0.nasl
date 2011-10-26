#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#

 desc["english"] = "
Synopsis :

The remote service is prone to information disclosure. 

Description :

The remote host is running a 'finger' service that suffers from an
information disclosure vulnerability.  Specifically, it allows an
unauthenticated attacker to display a list of accounts on the remote
host that have never been used.  This list can help an attacker to
guess the operating system type and also focus his attacks. 

Solution : 

Filter access to this port, upgrade the finger server, or disable it
entirely. 

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";


if(description)
{
 script_id(10069);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-0197");
 name["english"] = "Finger zero at host Information Disclosure Vulnerability";
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Finger 0@host feature";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Finger abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  # Cisco
  data = recv(socket:soc, length:2048, timeout:5);
  if(data)exit(0);
  buf = string("0\r\n");
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:65535);
  close(soc);

  if (
    strlen(data) > 150 && 
    egrep(pattern:'(^|[ \t]+)(adm|bin|daemon|lp|sys)[ \t]', string:data)
  ) {
    if (report_verbosity > 1) {
      report = string(
        desc,
        "\n",
        "\n",
        "Plugin output :\n",
        "\n",
        data
      );
    }
    else {
      report = desc;
    }
    security_warning(port:port, data:report);
    set_kb_item(name:"finger/0@host", value:TRUE);
  }
 }
}
