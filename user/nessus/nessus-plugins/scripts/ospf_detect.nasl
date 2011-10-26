# This plugin was written by Michel Arboi <arboi@alussinan.org>
# It is released under the GNU Public Licence (GPLv2)
# 
# RFC 1247 / RFC 2328 (OSPF v2)
# The OSPF protocol runs directly over IP, using IP protocol 89.
# Routing protocol packets should always be sent with the IP TOS field set
# to 0.
#
# Table 8: OSPF packet types.
#    1      Hello                  Discover/maintain  neighbors             
#    2      Database Description   Summarize database contents              
#    3      Link State Request     Database download                        
#    4      Link State Update      Database update                          
#    5      Link State Ack         Flooding acknowledgment
#

if(description)
{
  script_id(11906);
  script_version ("$Revision: 1.12 $");

  name["english"] = "OSPF detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote host is running an OSPF (Open Shortest Path First) agent.

Description :

The remote host is running OSPF, a popular routing protocol.

Solution :

If the remote service is not used, disable it.  

Risk factor : 

None";



  script_description(english:desc["english"]);
 
  summary["english"] = "Listen to OSPF packets";
  script_summary(english:summary["english"]);
  script_category(ACT_GATHER_INFO); 
  script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
  script_family(english:"Service detection");
  script_require_keys("Settings/ThoroughTests");
  exit(0);
}

##include("dump.inc");

include('global_settings.inc');

if ( ! thorough_tests)
{
 log_print('ospf_detect.nasl is enabled in "Thorough tests" mode only\n');
 exit(0);
}

if ( islocalhost() ) exit(0);
if ( ! islocalnet() ) exit(0);

if (! defined_func("join_multicast_group")) exit(0);

join_multicast_group("224.0.0.5");	# AllSPFRouters
join_multicast_group("224.0.0.6");	# AllDRouters
# join_multicast_group is necessary, because pcap_next does not put the 
# interface in promiscuous mode

function clean_exit()
{
  leave_multicast_group("224.0.0.5");
  leave_multicast_group("224.0.0.6");
  exit(0);
}

function extract_ip_addr(pkt, off)
{
  # This avoids a dirty warning, but there is definitely a problem somewhere
  # Why do I receive short OSPF Hello packets?
  if (off + 4 > strlen(pkt))
    return '0.0.0.0';

  return
	strcat(	ord(pkt[off+0]), ".", 
		ord(pkt[off+1]), ".", 
		ord(pkt[off+2]), ".", 
		ord(pkt[off+3]));
}

f = "ip proto 89 and src " + get_host_ip();
p = pcap_next(pcap_filter: f, timeout: 5);
if (isnull(p)) clean_exit();

##dump(ddata: p, dtitle: "IP");

hl = ord(p[0]) & 0xF; hl *= 4;
ospf = substr(p, hl);

##dump(ddata: ospf, dtitle: "OSPF");

head = substr(ospf, 0, 24);
data = substr(ospf, 24);

# OSPH header
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |   Version #   |     Type      |         Packet length         |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                          Router ID                            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                           Area ID                             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |           Checksum            |             AuType            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Authentication                          |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Authentication                          |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#

ver = ord(head[0]);
type = ord(head[1]);
len = ord(head[2]) * 256 + ord(head[3]);
rep = strcat('\nAn OSPF v', ver, ' agent is running on this host.\n');


# OSPF Hello packet
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                        Network Mask                           |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |         HelloInterval         |    Options    |    Rtr Pri    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                     RouterDeadInterval                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      Designated Router                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                   Backup Designated Router                    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                          Neighbor                             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

if (type == 1)
{
  mask = extract_ip_addr(pkt: data, off: 0);
  rep += strcat('The netmask is ', mask, '\n');
  dr = extract_ip_addr(pkt: data, off: 12);
  if (dr != '0.0.0.0')
    rep += strcat('The Designated Router is ', dr, '\n');
  bdr = extract_ip_addr(pkt: data, off: 16);
  if (bdr != '0.0.0.0')
    rep += strcat('The Backup Designated Router is ', dr, '\n');
  n = extract_ip_addr(pkt: data, off: 20);
  if (n != '0.0.0.0')
    rep += strcat('Neighbor ', n, ' has been seen\n');
}

rep += '\nRisk factor : Low';
security_note(port: 0, protocol: "ospf", data: rep);
clean_exit();
