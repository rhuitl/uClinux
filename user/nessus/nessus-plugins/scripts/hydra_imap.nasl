#TRUSTED 84379a8e12f8ca85600740cf6e08769aba957e0c96d84379de5ef21bd4bca020dd7d79609a094784cb66da037850a975a819e4294cb3eca159e855d4d3f5ce8579347c444c9c335202cc2f558cd7aa3ee479f4234c06d853c9c8026980589d61ecf93256a929bfd8dbe531669ea6c2510364c89dfcc290cb360201efa9c868ca07b18caac5df6b04decb81c319089fa047e58293593f2d919a89544bd4ae0a6f5649c7dea9dfbbc01fe8a1603e0382d21461d9a2e87eb161c82cd9d1c1e79e0b71410c9162e33c5e4a839de8e405a3c3fdd70597e5238545e5e1f69f7c68c034dae4e6109f3cef409f51618bf3697e2398d9e3775d421ac4a75c1578427fb1e67caacf3a45e068ac6d4d8987775eb1104bface3f6ff82405a25dc87d53794644ed69dc3fd44dcca107784bbe56de56496debbdd0749aa3e227cd3f100616fe0c4782a9404b6636f2c4e5a180de7b2432a30bf84dfeba7e8927a503f6740d7584e350b5955d2e4aad57da8a03f12bcd7f973db391ce8e5b0e57ffa6afc831bb6abc1f7d36dcab0c31b550becdb99a05261e7ad2519f2ec1e08ad4acab826dab74fe0ad9c68a5751da6a94ae95c3c59d3275c630e9d7294df5c978b01a6050cdb6a5c78329bbc980b1bba48731aa9e76d554c5aadd91c88dd2406c59ae6d25d3dcbb3dd4757ccd19663d6d5bfbd7eb452c5c93852a994678f49fc633cf730da370
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15876);
 script_version ("1.2");
 name["english"] = "Hydra: IMAP";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find IMAP accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force IMAP authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/imap", 143);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/imap");
if (! port) port = 143;
if (! get_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-L"; argv[i++] = logins;
argv[i++] = "-P"; argv[i++] = passwd;
s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = "imap";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/imap/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following IMAP accounts:\n' + report);
