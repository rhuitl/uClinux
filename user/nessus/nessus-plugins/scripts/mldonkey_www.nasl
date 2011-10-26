#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# Note: this script is not very useful because mldonkey only allows
# connections from localhost by default


if(description)
{
  script_id(11125);
  script_version ("$Revision: 1.6 $");
 
  script_name(english:"mldonkey www");
 
  desc["english"] = "
mldonkey web interface might be running on this port. This peer to peer 
software is used to share files.
1. This may be illegal.
2. You may have access to confidential files
3. It may eat too much bandwidth


Solution: disable it

Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect mldonkey www interface";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
  family["english"] = "Peer-To-Peer File Sharing";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 4080);

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:4080);

foreach port (ports)
{
 banner = get_http_banner(port: port);
 if (banner && ("MLdonkey" >< banner)) security_warning(port);
}
