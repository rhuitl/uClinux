#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

A DB2 discovery server is listening on the remote host. 

Description :

The remote host is running a DB2 discovery service.  DB2 is a
commercial database from IBM, and the discovery service is used by DB2
to locate databases across a network. 

See also :

http://www.ibm.com/software/data/db2/udb/

Risk factor :

None";


if (description)
{
  script_id(22017);
  script_version("$Revision: 1.1 $");

  script_name(english:"DB2 Discovery Service Detection");
  script_summary(english:"Detects a DB2 Discovery Service");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  exit(0);
}


include("misc_func.inc");


port = 523;


function get_null_string(blob, pos)
{
  local_var i, tmp;

  if (isnull(pos)) pos = 0;

  tmp = NULL;
  for (i=pos; i<strlen(blob); i++)
  {
    if (ord(blob[i]) != 0)
      tmp += blob[i];
    else
      break;
  }
  return tmp;
}


# Try to get some interesting information.
#
# - level identifier (ie, version).
soc = open_sock_udp(port);
req = raw_string("DB2GETADDR", 0, "SQL05000", 0);
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);


# If the response looks right..
if (
  strlen(res) >= 16 &&
  stridx(res, raw_string("DB2RETADDR", 0)) == 0
)
{
  if (strlen(res) >= 0x120)
  {
    # Extract some info from the response packet.
    #
    # nb: from <http://publib.boulder.ibm.com/infocenter/db2luw/v8/index.jsp?topic=/com.ibm.db2.udb.common.doc/common/aboutdialog.htm>, 
    #     Product identifier: identifies the DB2 Administration Server in 
    #     the format 'ppvvrrm', where 'ppp' is the product, 'vv' is the 
    #     version, 'rr' is the release, and 'm' is the modification level.
    prod  = get_null_string(blob:res, pos:11);
    node = get_null_string(blob:res, pos:20);

    # Register and report the service.
    register_service(port:port, ipproto:"udp", proto:"db2_ds");

    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "  Node name :          ", node, "\n",
      "  Product identifier : ", prod, "\n",
      "\n"
    );
  }
  else report = desc;

  security_note(port:port, proto:"udp", data:report);
}
