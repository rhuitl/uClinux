# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if(description)
{
 script_id(11090);
 script_version ("$Revision: 1.6 $");
 name["english"] = "AppSocket DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
It seems that it is possible to lock out your printer from the
network by opening a few connections and keeping them open.

** Note that the AppSocket protocol is so crude that Nessus
** cannot check if it is really running behind this port.

Solution : Change your settings or firewall your printer
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Too many AppSocket connections";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(35, 2501, 9100);
 exit(0);
}


include('global_settings.inc');
if ( report_paranoia == 0 ) exit(0);
#
function test_app_socket(port)
{
  #display("Testing port ", port, "\n");
  if (! get_port_state(port)) return(0);

  soc = open_sock_tcp(port);
  if (! soc) return(0);

  # Don't close...
  s[0] = soc;

  for (i = 1; i < 16; i = i+1)
  {
    soc = open_sock_tcp(port);
    if (! soc)
    {
      security_warning(port);
      for (j = 0; j < i; j=j+1) close(s[j]);
      return(1);
    }
    sleep(1);	# Make inetd (& others) happy!
    s[i] = soc;
  }
  for (j = 0; j < i; j=j+1) close(s[j]);
  return (0);
}

test_app_socket(port: 35);
test_app_socket(port: 2501);
test_app_socket(port: 9100);

