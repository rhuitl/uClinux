#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20094);
 script_version ("$Revision: 1.8 $");

 
 name["english"] = "VMWare Host";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host seems to be a VMWare virtual machine.

Description :

The remote host seems to be a VMWare virtual machine running
the Microsoft Windows Operating system. Since it is physically 
accessible through the network, you should ensure that its 
configuration matches the one of your corporate security policy.

Risk factor :

None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if the remote host is VMWare";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl", "ssh_get_info.nasl", "snmp_ifaces.nasl");
 exit(0);
}

ether = get_kb_item("SMB/mac_addr");
if (! ether) 
{
  if ( islocalnet() ) ether = get_kb_item("ARP/mac_addr");

  if ( ! ether )
  {
   buf = get_kb_item("Host/ifconfig");
   if ( buf ) 
    {
     mac = egrep(pattern:"(ether|hwaddr) [0-9a-f:]+", string:buf, icase:TRUE);
     if ( mac )
	{
	  array = split(mac, sep:'\n', keep:FALSE);
	  foreach line ( array ) {
			ether += tolower(ereg_replace(pattern:".*(hwaddr|ether) ([0-9a-f:]+).*", replace:"\2", string:line, icase:TRUE)) + '\n';
			}
	}
	
    }
  }

  if ( ! ether )
  {
    i = 0;
    while ( TRUE )
     {
	 str = get_kb_item("SNMP/ifPhysAddress/" + i );
	 if ( str ) ether += str + '\n';
	 else break;
	 i ++;
     }
  }
}
if ( ! ether ) exit(0);
# -> http://standards.ieee.org/regauth/oui/index.shtml
if ( egrep(pattern:"^00:(0c:29|05:69|50:56)", string:ether, icase:TRUE) ) security_note(0);
