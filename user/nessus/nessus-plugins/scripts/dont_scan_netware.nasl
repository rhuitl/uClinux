#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22482);
  script_version("$Revision: 1.2 $");

  script_name(english:"Do not scan Novell Netware");
  script_summary(english:"Marks Novell Netware systems as dead");

  desc = "
Synopsis :

The remote host appears to be running Novell Netware and will not be
scanned. 

Description :

The remote host appears to be running Novell Netware.  This operating
system has a history of crashing or otherwise being adversely affected
by scans.  As a result, the scan has been disabled against this host. 

See also :

http://support.novell.com/cgi-bin/search/searchtid.cgi?/2972443.htm

Solution :

If you want to scan the remote host enable the option 'Scan Novell Netware hosts'
in your Nessus client and re-scan it. 

Risk factor :

None";
  script_description(english:desc);

  script_category(ACT_SETTINGS);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
  script_dependencie("dont_scan_settings.nasl");

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("snmp_func.inc");

if (  get_kb_item("Scan/Do_Scan_Novell") ) exit(0);



# Check SNMP.
if (get_kb_item("SNMP/community"))
{
  port = get_kb_item("SNMP/port"); 
  community = get_kb_item("SNMP/community");
  soc = open_sock_udp(port);
  if (soc) 
  {
    desc = snmp_request(socket:soc, community:community, oid:"1.3.6.1.4.1.23.1.6");
    close(soc);
    if (desc && "Novell NetWare" >< desc)
    {
      set_kb_item(name:"Host/dead", value:TRUE);
      security_note(port:0);
      exit(0);
    }
  }
}



# Check web servers.
foreach port (make_list(81, 8009))
{
  if (get_port_state(port))
  {
    banner = http_send_recv(port:port, data:string("GET / HTTP/1.0\r\n\r\n"));
    if ("Server: NetWare HTTP Stack" >< banner)
    {
      set_kb_item(name:"Host/dead", value:TRUE);
      security_note(port:0);
      exit(0);
    }
  }
}

foreach port (make_list(80))
{
  if (get_port_state(port))
  {
    banner = http_send_recv(port:port, data:string("GET / HTTP/1.0\r\n\r\n"));
    if (
      "(NETWARE)" >< banner &&
      egrep(pattern:"^Server: Apache(/[^ ]*)? \(NETWARE\)", string:banner)
    )
    {
      set_kb_item(name:"Host/dead", value:TRUE);
      security_note(port:0);
      exit(0);
    }
  }
}
