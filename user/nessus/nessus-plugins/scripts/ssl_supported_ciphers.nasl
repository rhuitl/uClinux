#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote service encrypts communications using SSL.

Description :

This script detects which SSL ciphers are supported by the remote
service for encrypting communications. 

See also :

http://www.openssl.org/docs/apps/ciphers.html

Risk factor : 

None";


  desc_weak = "
Synopsis :

The remote service supports the use of weak SSL ciphers.

Description :

The remote host supports the use of SSL ciphers that
offer either weak encryption or no encryption at all.

See also :

http://www.openssl.org/docs/apps/ciphers.html

Solution :

Reconfigure the affected application if possible to avoid use of 
weak ciphers.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";


if (description)
{
  script_id(21643);
  script_version("$Revision: 1.9 $");

  script_name(english:"Supported SSL Ciphers Suites");
  script_summary(english:"Checks which SSL ciphers suites are supported");
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes");

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");


set_byte_order(BYTE_ORDER_BIG_ENDIAN);


# Make sure the port is open and supports SSL.
if (COMMAND_LINE) port = 443;
else port = get_kb_item("Transport/SSL");
if (!port || !get_port_state(port)) exit(0);
encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && (encaps < ENCAPS_SSLv2 || encaps > ENCAPS_TLSv1)) exit(0);


# Cipher strength categorizations.
cat = 0;
NULL_STRENGTH = cat;
labels[cat] = "Null Ciphers (no encryption)";
EXPORT_STRENGTH = ++cat;
labels[cat] = "Export Ciphers";
LOW_STRENGTH = ++cat;
labels[cat] = "Low Strength Ciphers (excluding export, < 128-bit key)";
MEDIUM_STRENGTH = ++cat;
labels[cat] = "Medium Strength Ciphers (128-bit key)";
HIGH_STRENGTH = ++cat;
labels[cat] = "High Strength Ciphers (> 128-bit key)";
max_strength = ++cat;
labels[cat] = "Uncategorized Ciphers";

# Cipher descriptions; fields are
#   <OpenSSL ciphername>
#   <protocol version>
#   Kx=<key exchange>
#   Au=<authentication>
#   Enc=<symmetric encryption method>
#   Mac=<message authentication code>
#   <export flag>
labels["SSL2_CK_NULL_WITH_MD5"]                    = "NULL-MD5|SSLv2|Kx=RSA|Au=RSA|Enc=None|Mac=MD5";
labels["SSL2_CK_RC4_128_WITH_MD5"]                 = "RC4-MD5|SSLv2|Kx=RSA|Au=RSA|Enc=RC4(128)|Mac=MD5";
labels["SSL2_CK_RC4_128_EXPORT40_WITH_MD5"]        = "EXP-RC4-MD5|SSLv2|Kx=RSA(512)|Au=RSA|Enc=RC4(40)|Mac=MD5|export";
labels["SSL2_CK_RC2_128_CBC_WITH_MD5"]             = "RC2-CBC-MD5|SSLv2|Kx=RSA|Au=RSA|Enc=RC2(128)|Mac=MD5";
labels["SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5"]    = "EXP-RC2-CBC-MD5|SSLv2|Kx=RSA(512)|Au=RSA|Enc=RC2(40)|Mac=MD5|export";
labels["SSL2_CK_IDEA_128_CBC_WITH_MD5"]            = "IDEA-CBC-MD5|SSLv2|Kx=RSA|Au=RSA|Enc=IDEA(128)|Mac=MD5";
labels["SSL2_CK_DES_64_CBC_WITH_MD5"]              = "DES-CBC-MD5|SSLv2|Kx=RSA|Au=RSA|Enc=DES(56)|Mac=MD5";
labels["SSL2_CK_DES_64_CBC_WITH_SHA"]              = "DES-CBC-SHA|SSLv2|Kx=RSA|Au=RSA|Enc=DES(56)|Mac=SHA1";
labels["SSL2_CK_DES_192_EDE3_CBC_WITH_MD5"]        = "DES-CBC3-MD5|SSLv2|Kx=RSA|Au=RSA|Enc=3DES(168)|Mac=MD5";
labels["SSL2_CK_DES_192_EDE3_CBC_WITH_SHA"]        = "DES-CBC3-SHA|SSLv2|Kx=RSA|Au=RSA|Enc=3DES(168)|Mac=SHA1";
labels["SSL2_CK_RC4_64_WITH_MD5"]                  = "RC4-64-MD5|SSLv2|Kx=RSA|Au=RSA|Enc=RC4(64)|Mac=MD5";
labels["SSL2_CK_DES_64_CFB64_WITH_MD5_1"]          = "DES-CFB-M1|SSLv2|Kx=RSA|Au=RSA|Enc=DES(56)|Mac=MD5 with 1 byte";
labels["SSL2_CK_NULL"]                             = "NULL|SSLv2|Kx=RSA|Au=RSA|Enc=None|Mac=None";
labels["SSL3_CK_RSA_NULL_MD5"]                     = "NULL-MD5|SSLv3|Kx=RSA|Au=RSA|Enc=None|Mac=MD5";
labels["SSL3_CK_RSA_NULL_SHA"]                     = "NULL-SHA|SSLv3|Kx=RSA|Au=RSA|Enc=None|Mac=SHA1";
labels["SSL3_CK_RSA_RC4_40_MD5"]                   = "EXP-RC4-MD5|SSLv3|Kx=RSA(512)|Au=RSA|Enc=RC4(40)|Mac=MD5|export";
labels["SSL3_CK_RSA_RC4_128_MD5"]                  = "RC4-MD5|SSLv3|Kx=RSA|Au=RSA|Enc=RC4(128)|Mac=MD5";
labels["SSL3_CK_RSA_RC4_128_SHA"]                  = "RC4-SHA|SSLv3|Kx=RSA|Au=RSA|Enc=RC4(128)|Mac=SHA1";
labels["SSL3_CK_RSA_RC2_40_MD5"]                   = "EXP-RC2-CBC-MD5|SSLv3|Kx=RSA(512)|Au=RSA|Enc=RC2(40)|Mac=MD5|export";
labels["SSL3_CK_RSA_IDEA_128_SHA"]                 = "IDEA-CBC-SHA|SSLv3|Kx=RSA|Au=RSA|Enc=IDEA(128)|Mac=SHA1";
labels["SSL3_CK_RSA_DES_40_CBC_SHA"]               = "EXP-DES-CBC-SHA|SSLv3|Kx=RSA(512)|Au=RSA|Enc=DES(40)|Mac=SHA1|export";
labels["SSL3_CK_RSA_DES_64_CBC_SHA"]               = "DES-CBC-SHA|SSLv3|Kx=RSA|Au=RSA|Enc=DES(56)|Mac=SHA1";
labels["SSL3_CK_RSA_DES_192_CBC3_SHA"]             = "DES-CBC3-SHA|SSLv3|Kx=RSA|Au=RSA|Enc=3DES(168)|Mac=SHA1";
labels["SSL3_CK_DH_DSS_DES_40_CBC_SHA"]            = "EXP-DH-DSS-DES-CBC-SHA|SSLv3|Kx=DH(512)|Au=DSS|Enc=DES(40)|Mac=SHA1|export";
labels["SSL3_CK_DH_DSS_DES_64_CBC_SHA"]            = "DH-DSS-DES-CBC-SHA|SSLv3|Kx=DH|Au=DSS|Enc=DES(56)|Mac=SHA1";
labels["SSL3_CK_DH_DSS_DES_192_CBC3_SHA"]          = "DH-DSS-DES-CBC3-SHA|SSLv3|Kx=DH|Au=DSS|Enc=3DES(168)|Mac=SHA1";
labels["SSL3_CK_DH_RSA_DES_40_CBC_SHA"]            = "EXP-DH-RSA-DES-CBC-SHA|SSLv3|Kx=DH(512)|Au=RSA|Enc=DES(40)|Mac=SHA1|export";
labels["SSL3_CK_DH_RSA_DES_64_CBC_SHA"]            = "DH-RSA-DES-CBC-SHA|SSLv3|Kx=DH|Au=RSA|Enc=DES(56)|Mac=SHA1";
labels["SSL3_CK_DH_RSA_DES_192_CBC3_SHA"]          = "DH-RSA-DES-CBC3-SHA|SSLv3|Kx=DH|Au=RSA|Enc=3DES(168)|Mac=SHA1";
labels["SSL3_CK_EDH_DSS_DES_40_CBC_SHA"]           = "EXP-EDH-DSS-DES-CBC-SHA|SSLv3|Kx=DH(512)|Au=DSS|Enc=DES(40)|Mac=SHA1|export";
labels["SSL3_CK_EDH_DSS_DES_64_CBC_SHA"]           = "EDH-DSS-DES-CBC-SHA|SSLv3|Kx=DH|Au=DSS|Enc=DES(56)|Mac=SHA1";
labels["SSL3_CK_EDH_DSS_DES_192_CBC3_SHA"]         = "EDH-DSS-DES-CBC3-SHA|SSLv3|Kx=DH|Au=DSS|Enc=3DES(168)|Mac=SHA1";
labels["SSL3_CK_EDH_RSA_DES_40_CBC_SHA"]           = "EXP-EDH-RSA-DES-CBC-SHA|SSLv3|Kx=DH(512)|Au=RSA|Enc=DES(40)|Mac=SHA1|export";
labels["SSL3_CK_EDH_RSA_DES_64_CBC_SHA"]           = "EDH-RSA-DES-CBC-SHA|SSLv3|Kx=DH|Au=RSA|Enc=DES(56)|Mac=SHA1";
labels["SSL3_CK_EDH_RSA_DES_192_CBC3_SHA"]         = "EDH-RSA-DES-CBC3-SHA|SSLv3|Kx=DH|Au=RSA|Enc=3DES(168)|Mac=SHA1";
labels["SSL3_CK_ADH_RC4_40_MD5"]                   = "EXP-ADH-RC4-MD5|SSLv3|Kx=DH(512)|Au=None|Enc=RC4(40)|Mac=MD5|export";
labels["SSL3_CK_ADH_RC4_128_MD5"]                  = "ADH-RC4-MD5|SSLv3|Kx=DH|Au=None|Enc=RC4(128)|Mac=MD5";
labels["SSL3_CK_ADH_DES_40_CBC_SHA"]               = "EXP-ADH-DES-CBC-SHA|SSLv3|Kx=DH(512)|Au=None|Enc=DES(40)|Mac=SHA1|export";
labels["SSL3_CK_ADH_DES_64_CBC_SHA"]               = "ADH-DES-CBC-SHA|SSLv3|Kx=DH|Au=None|Enc=DES(56)|Mac=SHA1";
labels["SSL3_CK_ADH_DES_192_CBC_SHA"]              = "ADH-DES-CBC3-SHA|SSLv3|Kx=DH|Au=None|Enc=3DES(168)|Mac=SHA1";
labels["SSL3_CK_FZA_DMS_NULL_SHA"]                 = "FZA-NULL-SHA|SSLv3|Kx=KEA|Au=DSA|Enc=None|Mac=SHA1";
labels["SSL3_CK_FZA_DMS_FZA_SHA"]                  = "FZA-FZA-CBC-SHA|SSLv3|Kx=KEA|Au=DSA|Enc=SKIPJACK(80)|Mac=SHA1";
labels["SSL3_CK_KRB5_DES_64_CBC_SHA"]              = "KRB5-DES-CBC-SHA|SSLv3|Kx=KRB5|Au=KRB5|Enc=DES(56)|Mac=SHA1";
labels["SSL3_CK_KRB5_DES_192_CBC3_SHA"]            = "KRB5-DES-CBC3-SHA|SSLv3|Kx=KRB5|Au=KRB5|Enc=3DES(168)|Mac=SHA1";
labels["SSL3_CK_KRB5_RC4_128_SHA"]                 = "KRB5-RC4-SHA|SSLv3|Kx=KRB5|Au=KRB5|Enc=RC4(128)|Mac=SHA1";
labels["SSL3_CK_KRB5_IDEA_128_CBC_SHA"]            = "KRB5-IDEA-CBC-SHA|SSLv3|Kx=KRB5|Au=KRB5|Enc=IDEA(128)|Mac=SHA1";
labels["SSL3_CK_KRB5_DES_64_CBC_MD5"]              = "KRB5-DES-CBC-MD5|SSLv3|Kx=KRB5|Au=KRB5|Enc=DES(56)|Mac=MD5";
labels["SSL3_CK_KRB5_DES_192_CBC3_MD5"]            = "KRB5-DES-CBC3-MD5|SSLv3|Kx=KRB5|Au=KRB5|Enc=3DES(168)|Mac=MD5";
labels["SSL3_CK_KRB5_RC4_128_MD5"]                 = "KRB5-RC4-MD5|SSLv3|Kx=KRB5|Au=KRB5|Enc=RC4(128)|Mac=MD5";
labels["SSL3_CK_KRB5_IDEA_128_CBC_MD5"]            = "KRB5-IDEA-CBC-MD5|SSLv3|Kx=KRB5|Au=KRB5|Enc=IDEA(128)|Mac=MD5";
labels["SSL3_CK_KRB5_DES_40_CBC_SHA"]              = "EXP-KRB5-DES-CBC-SHA|SSLv3|Kx=KRB5|Au=KRB5|Enc=DES(40)|Mac=SHA1|export";
labels["SSL3_CK_KRB5_RC2_40_CBC_SHA"]              = "EXP-KRB5-RC2-CBC-SHA|SSLv3|Kx=KRB5|Au=KRB5|Enc=RC2(40)|Mac=SHA1|export";
labels["SSL3_CK_KRB5_RC4_40_SHA"]                  = "EXP-KRB5-RC4-SHA|SSLv3|Kx=KRB5|Au=KRB5|Enc=RC4(40)|Mac=SHA1|export";
labels["SSL3_CK_KRB5_DES_40_CBC_MD5"]              = "EXP-KRB5-DES-CBC-MD5|SSLv3|Kx=KRB5|Au=KRB5|Enc=DES(40)|Mac=MD5|export";
labels["SSL3_CK_KRB5_RC2_40_CBC_MD5"]              = "EXP-KRB5-RC2-CBC-MD5|SSLv3|Kx=KRB5|Au=KRB5|Enc=RC2(40)|Mac=MD5|export";
labels["SSL3_CK_KRB5_RC4_40_MD5"]                  = "EXP-KRB5-RC4-MD5|SSLv3|Kx=KRB5|Au=KRB5|Enc=RC4(40)|Mac=MD5|export";
labels["TLS1_CK_NULL_WITH_NULL_NULL"]              = "n/a|TLSv1|Kx=None|Au=None|Enc=None|Mac=None";
labels["TLS1_CK_RSA_WITH_NULL_MD5"]                = "NULL-MD5|TLSv1|Kx=RSA|Au=RSA|Enc=None|Mac=MD5";
labels["TLS1_CK_RSA_WITH_NULL_SHA"]                = "NULL-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=None|Mac=SHA1";
labels["TLS1_CK_RSA_EXPORT_WITH_RC4_40_MD5"]       = "EXP-RC4-MD5|TLSv1|Kx=RSA(512)|Au=RSA|Enc=RC4(40)|Mac=MD5|export";
labels["TLS1_CK_RSA_WITH_RC4_128_MD5"]             = "RC4-MD5|TLSv1|Kx=RSA|Au=RSA|Enc=RC4(128)|Mac=MD5";
labels["TLS1_CK_RSA_WITH_RC4_128_SHA"]             = "RC4-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=RC4(128)|Mac=SHA1";
labels["TLS1_CK_RSA_EXPORT_WITH_RC2_CBC_40_MD5"]   = "EXP-RC2-CBC-MD5|TLSv1|Kx=RSA(512)|Au=RSA|Enc=RC2(40)|Mac=MD5|export";
labels["TLS1_CK_RSA_WITH_IDEA_CBC_SHA"]            = "IDEA-CBC-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=IDEA(128)|Mac=SHA1";
labels["TLS1_CK_RSA_EXPORT_WITH_DES40_CBC_SHA"]    = "EXP-DES-CBC-SHA|TLSv1|Kx=RSA(512)|Au=RSA|Enc=DES(40)|Mac=SHA1|export";
labels["TLS1_CK_RSA_WITH_DES_CBC_SHA"]             = "DES-CBC-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=DES(56)|Mac=SHA1";
labels["TLS1_CK_RSA_WITH_3DES_EDE_CBC_SHA"]        = "DES-CBC3-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"] = "EXP-DH-DSS-DES-CBC-SHA|TLSv1|Kx=DH(512)|Au=DSS|Enc=DES(40)|Mac=SHA1|export";
labels["TLS1_CK_DH_DSS_WITH_DES_CBC_SHA"]          = "DH-DSS-DES-CBC-SHA|TLSv1|Kx=DH|Au=DSS|Enc=DES(56)|Mac=SHA1";
labels["TLS1_CK_DH_DSS_WITH_3DES_EDE_CBC_SHA"]     = "DH-DSS-DES-CBC3-SHA|TLSv1|Kx=DH|Au=DSS|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"] = "EXP-DH-RSA-DES-CBC-SHA|TLSv1|Kx=DH(512)|Au=RSA|Enc=DES(40)|Mac=SHA1|export";
labels["TLS1_CK_DH_RSA_WITH_DES_CBC_SHA"]          = "DH-RSA-DES-CBC-SHA|TLSv1|Kx=DH|Au=RSA|Enc=DES(56)|Mac=SHA1";
labels["TLS1_CK_DH_RSA_WITH_3DES_EDE_CBC_SHA"]     = "DH-RSA-DES-CBC3-SHA|TLSv1|Kx=DH|Au=RSA|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"]= "EXP-EDH-DSS-DES-CBC-SHA|TLSv1|Kx=DH(512)|Au=DSS|Enc=DES(40)|Mac=SHA1|export";
labels["TLS1_CK_DHE_DSS_WITH_DES_CBC_SHA"]         = "EDH-DSS-DES-CBC-SHA|TLSv1|Kx=DH|Au=DSS|Enc=DES(56)|Mac=SHA1";
labels["TLS1_CK_DHE_DSS_WITH_3DES_EDE_CBC_SHA"]    = "EDH-DSS-DES-CBC3-SHA|TLSv1|Kx=DH|Au=DSS|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"]= "EXP-EDH-RSA-DES-CBC-SHA|TLSv1|Kx=DH(512)|Au=RSA|Enc=DES(40)|Mac=SHA1|export";
labels["TLS1_CK_DHE_RSA_WITH_DES_CBC_SHA"]         = "EDH-RSA-DES-CBC-SHA|TLSv1|Kx=DH|Au=RSA|Enc=DES(56)|Mac=SHA1";
labels["TLS1_CK_DHE_RSA_WITH_3DES_EDE_CBC_SHA"]    = "EDH-RSA-DES-CBC3-SHA|TLSv1|Kx=DH|Au=RSA|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_DH_anon_EXPORT_WITH_RC4_40_MD5"]   = "EXP-ADH-RC4-MD5|TLSv1|Kx=DH(512)|Au=None|Enc=RC4(40)|Mac=MD5|export";
labels["TLS1_CK_DH_anon_WITH_RC4_128_MD5"]         = "ADH-RC4-MD5|TLSv1|Kx=DH|Au=None|Enc=RC4(128)|Mac=MD5";
labels["TLS1_CK_DH_anon_EXPORT_WITH_DES40_CBC_SHA"]= "EXP-ADH-DES-CBC-SHA|TLSv1|Kx=DH(512)|Au=None|Enc=DES(40)|Mac=SHA1|export";
labels["TLS1_CK_DH_anon_WITH_DES_CBC_SHA"]         = "ADH-DES-CBC-SHA|TLSv1|Kx=DH|Au=None|Enc=DES(56)|Mac=SHA1";
labels["TLS1_CK_DH_anon_WITH_3DES_EDE_CBC_SHA"]    = "ADH-DES-CBC3-SHA|TLSv1|Kx=DH|Au=None|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_KRB5_WITH_DES_CBC_SHA"]            = "KRB5-DES-CBC-SHA|TLSv1|Kx=KRB5|Au=KRB5|Enc=DES(56)|MAC=SHA1";
labels["TLS1_CK_KRB5_WITH_3DES_EDE_CBC_SHA"]       = "KRB5-DES-CBC3-SHA|TLSv1|Kx=KRB5|Au=KRB5|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_KRB5_WITH_RC4_128_SHA"]            = "KRB5-RC4-SHA|TLSv1|Kx=KRB5|Au=KRB5|Enc=RC4(128)|Mac=SHA1";
labels["TLS1_CK_KRB5_WITH_IDEA_CBC_SHA"]           = "KRB5-IDEA-CBC-SHA|TLSv1|Kx=KRB5|Au=KRB5|Enc=IDEA(128)|Mac=SHA1";
labels["TLS1_CK_KRB5_WITH_DES_CBC_MD5"]            = "KRB5-DES-CBC-MD5|TLSv1|Kx=KRB5|Au=KRB5|Enc=DES(56)|Mac=MD5";
labels["TLS1_CK_KRB5_WITH_3DES_EDE_CBC_MD5"]       = "KRB5-DES-CBC3-MD5|TLSv1|Kx=KRB5|Au=KRB5|Enc=3DES(168)|Mac=MD5";
labels["TLS1_CK_KRB5_WITH_RC4_128_MD5"]            = "KRB5-RC4-MD5|TLSv1|Kx=KRB5|Au=KRB5|Enc=RC4(128)|Mac=MD5";
labels["TLS1_CK_KRB5_WITH_IDEA_CBC_MD5"]           = "KRB5-IDEA-CBC-MD5|TLSv1|Kx=KRB5|Au=KRB5|Enc=IDEA(128)|Mac=MD5";
labels["TLS1_CK_KRB5_EXPORT_WITH_DES_CBC_40_SHA"]  = "EXP-KRB5-DES-CBC-SHA|TLSv1|Kx=KRB5|Au=KRB5|Enc=DES(40)|Mac=SHA1|export";
labels["TLS1_CK_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"]  = "EXP-KRB5-RC2-CBC-SHA|TLSv1|Kx=KRB5|Au=KRB5|Enc=RC2(40)|Mac=SHA1|export";
labels["TLS1_CK_KRB5_EXPORT_WITH_RC4_40_SHA"]      = "EXP-KRB5-RC4-SHA|TLSv1|Kx=KRB5|Au=KRB5|Enc=RC4(40)|Mac=SHA1|export";
labels["TLS1_CK_KRB5_EXPORT_WITH_DES_CBC_40_MD5"]  = "EXP-KRB5-DES-CBC-MD5|TLSv1|Kx=KRB5|Au=KRB5|Enc=DES(40)|Mac=MD5|export";
labels["TLS1_CK_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"]  = "EXP-KRB5-RC2-CBC-MD5|TLSv1|Kx=KRB5|Au=KRB5|Enc=RC2(40)|Mac=MD5|export";
labels["TLS1_CK_KRB5_EXPORT_WITH_RC4_40_MD5"]      = "EXP-KRB5-RC4-MD5|TLSv1|Kx=KRB5|Au=KRB5|Enc=RC4(40)|Mac=MD5|export";
labels["TLS1_CK_RSA_WITH_AES_128_CBC_SHA"]         = "AES128-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=AES(128)|Mac=SHA1";
labels["TLS1_CK_DH_DSS_WITH_AES_128_CBC_SHA"]      = "DH-DSS-AES128-SHA|TLSv1|Kx=DH|Au=DSS|Enc=AES(128)|Mac=SHA1";
labels["TLS1_CK_DH_RSA_WITH_AES_128_CBC_SHA"]      = "DH-RSA-AES128-SHA|TLSv1|Kx=DH|Au=RSA|Enc=AES(128)|Mac=SHA1";
labels["TLS1_CK_DHE_DSS_WITH_AES_128_CBC_SHA"]     = "DHE-DSS-AES128-SHA|TLSv1|Kx=DH|Au=DSS|Enc=AES(128)|Mac=SHA1";
labels["TLS1_CK_DHE_RSA_WITH_AES_128_CBC_SHA"]     = "DHE-RSA-AES128-SHA|TLSv1|Kx=DH|Au=RSA|Enc=AES(128)|Mac=SHA1";
labels["TLS1_CK_DH_anon_WITH_AES_128_CBC_SHA"]     = "ADH-AES128-SHA|TLSv1|Kx=DH|Au=None|Enc=AES(128)|Mac=SHA1";
labels["TLS1_CK_RSA_WITH_AES_256_CBC_SHA"]         = "AES256-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=AES(256)|Mac=SHA1";
labels["TLS1_CK_DH_DSS_WITH_AES_256_CBC_SHA"]      = "DH-DSS-AES256-SHA|TLSv1|Kx=DH|Au=DSS|Enc=AES(256)|Mac=SHA1";
labels["TLS1_CK_DH_RSA_WITH_AES_256_CBC_SHA"]      = "DH-RSA-AES256-SHA|TLSv1|Kx=DH|Au=RSA|Enc=AES(256)|Mac=SHA1";
labels["TLS1_CK_DHE_DSS_WITH_AES_256_CBC_SHA"]     = "DHE-DSS-AES256-SHA|TLSv1|Kx=DH|Au=DSS|Enc=AES(256)|Mac=SHA1";
labels["TLS1_CK_DHE_RSA_WITH_AES_256_CBC_SHA"]     = "DHE-RSA-AES256-SHA|TLSv1|Kx=DH|Au=RSA|Enc=AES(256)|Mac=SHA1";
labels["TLS1_CK_DH_anon_WITH_AES_256_CBC_SHA"]     = "ADH-AES256-SHA|TLSv1|Kx=DH|Au=None|Enc=AES(256)|Mac=SHA1";
labels["TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5"]   = "EXP1024-RC4-MD5|TLSv1|Kx=RSA(1024)|Au=RSA|Enc=RC4(56)|Mac=MD5|export";
labels["TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"]= "EXP1024-RC2-CBC-MD5|TLSv1|Kx=RSA(1024)|Au=RSA|Enc=RC2(56)|Mac=MD5|export";
labels["TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA"]  = "EXP1024-DES-CBC-SHA|TLSv1|Kx=RSA(1024)|Au=RSA|Enc=DES(56)|Mac=SHA1|export";
labels["TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"]= "EXP1024-DHE-DSS-DES-CBC-SHA|TLSv1|Kx=DH(1024)|Au=DSS|Enc=DES(56)|Mac=SHA1|export";
labels["TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA"]   = "EXP1024-RC4-SHA|TLSv1|Kx=RSA(1024)|Au=RSA|Enc=RC4(56)|Mac=SHA1|export";
labels["TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"]= "EXP1024-DHE-DSS-RC4-SHA|TLSv1|Kx=DH(1024)|Au=DSS|Enc=RC4(56)|Mac=SHA1|export";
labels["TLS1_CK_DHE_DSS_WITH_RC4_128_SHA"]         = "DHE-DSS-RC4-SHA|TLSv1|Kx=DH|Au=DSS|Enc=RC4(128)|Mac=SHA1";
labels["TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA"]    = "n/a|TLSv1|Kx=RSA|Au=RSA|Enc=Camellia(128)|Mac=SHA1";
labels["TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"] = "n/a|TLSv1|Kx=DH|Au=DSS|Enc=Camellia(128)|Mac=SHA1";
labels["TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"] = "n/a|TLSv1|Kx=DH|Au=RSA|Enc=Camellia(128)|Mac=SHA1";
labels["TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"]= "n/a|TLSv1|Kx=DH|Au=DSS|Enc=Camellia(128)|Mac=SHA1";
labels["TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"]= "n/a|TLSv1|Kx=DH|Au=RSA|Enc=Camellia(128)|Mac=SHA1";
labels["TLS1_CK_DH_anon_WITH_CAMELLIA_128_CBC_SHA"]= "n/a|TLSv1|Kx=DH|Au=None|Enc=Camellia(128)|Mac=SHA1";
labels["TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA"]    = "n/a|TLSv1|Kx=RSA|Au=RSA|Enc=Camellia(256)|Mac=SHA1";
labels["TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"] = "n/a|TLSv1|Kx=DH|Au=DSS|Enc=Camellia(256)|Mac=SHA1";
labels["TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"] = "n/a|TLSv1|Kx=DH|Au=RSA|Enc=Camellia(256)|Mac=SHA1";
labels["TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"]= "n/a|TLSv1|Kx=DH|Au=DSS|Enc=Camellia(256)|Mac=SHA1";
labels["TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"]= "n/a|TLSv1|Kx=DH|Au=RSA|Enc=Camellia(256)|Mac=SHA1";
labels["TLS1_CK_DH_anon_WITH_CAMELLIA_256_CBC_SHA"]= "n/a|TLSv1|Kx=DH|Au=None|Enc=Camellia(256)|Mac=SHA1";
labels["TLS1_CK_PSK_WITH_RC4_128_SHA"]             = "n/a|TLSv1|Kx=PSK|Au=PSK|Enc=RC4(128)|Mac=SHA1";
labels["TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA"]        = "n/a|TLSv1|Kx=PSK|Au=PSK|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_PSK_WITH_AES_128_CBC_SHA"]         = "n/a|TLSv1|Kx=PSK|Au=PSK|Enc=AES(128)|Mac=SHA1";
labels["TLS1_CK_PSK_WITH_AES_256_CBC_SHA"]         = "n/a|TLSv1|Kx=PSK|Au=PSK|Enc=AES(256)|Mac=SHA1";
labels["TLS1_CK_DHE_PSK_WITH_RC4_128_SHA"]         = "n/a|TLSv1|Kx=DH|Au=PSK|Enc=RC4(128)|Mac=SHA1";
labels["TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA"]    = "n/a|TLSv1|Kx=DH|Au=PSK|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA"]     = "n/a|TLSv1|Kx=DH|Au=PSK|Enc=AES(128)|Mac=SHA1";
labels["TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA"]     = "n/a|TLSv1|Kx=DH|Au=PSK|Enc=AES(256)|Mac=SHA1";
labels["TLS1_CK_RSA_PSK_WITH_RC4_128_SHA"]         = "n/a|TLSv1|Kx=RSA|Au=PSK|Enc=RC4(128)|Mac=SHA1";
labels["TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA"]    = "n/a|TLSv1|Kx=RSA|Au=PSK|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA"]     = "n/a|TLSv1|Kx=RSA|Au=PSK|Enc=AES(128)|Mac=SHA1";
labels["TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA"]     = "n/a|TLSv1|Kx=RSA|Au=PSK|Enc=AES(256)|Mac=SHA1";
labels["TLS1_CK_RSA_WITH_SEED_CBC_SHA"]            = "n/a|TLSv1|Kx=RSA|Au=RSA|Enc=SEED(128)|Mac=SHA1";
labels["TLS1_CK_DH_DSS_WITH_SEED_CBC_SHA"]         = "n/a|TLSv1|Kx=DH|Au=DSS|Enc=SEED(128)|Mac=SHA1";
labels["TLS1_CK_DH_RSA_WITH_SEED_CBC_SHA"]         = "n/a|TLSv1|Kx=DH|Au=RSA|Enc=SEED(128)|Mac=SHA1";
labels["TLS1_CK_DHE_DSS_WITH_SEED_CBC_SHA"]        = "n/a|TLSv1|Kx=DH|Au=DSS|Enc=SEED(128)|Mac=SHA1";
labels["TLS1_CK_DHE_RSA_WITH_SEED_CBC_SHA"]        = "n/a|TLSv1|Kx=DH|Au=RSA|Enc=SEED(128)|Mac=SHA1";
labels["TLS1_CK_DH_anon_WITH_SEED_CBC_SHA"]        = "n/a|TLSv1|Kx=DH|Au=None|Enc=SEED(128)|Mac=SHA1";
labels["TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA"]         = "n/a|TLSv1|Kx=ECDH|Au=ECDSA|Enc=None|Mac=SHA1";
labels["TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA"]      = "n/a|TLSv1|Kx=ECDH|Au=ECDSA|Enc=RC4(128)|Mac=SHA1";
labels["TLS1_CK_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"] = "n/a|TLSv1|Kx=ECDH|Au=ECDSA|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA"]  = "n/a|TLSv1|Kx=ECDH|Au=ECDSA|Enc=AES(128)|Mac=SHA1";
labels["TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA"]  = "n/a|TLSv1|Kx=ECDH|Au=ECDSA|Enc=AES(256)|Mac=SHA1";
labels["TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA"]        = "n/a|TLSv1|Kx=ECDH|Au=ECDSA|Enc=None|Mac=SHA1";
labels["TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA"]     = "n/a|TLSv1|Kx=ECDH|Au=ECDSA|Enc=RC4(128)|Mac=SHA1";
labels["TLS1_CK_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"]= "n/a|TLSv1|Kx=ECDH|Au=ECDSA|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"] = "n/a|TLSv1|Kx=ECDH|Au=ECDSA|Enc=AES(128)|Mac=SHA1";
labels["TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"] = "n/a|TLSv1|Kx=ECDH|Au=ECDSA|Enc=AES(256)|Mac=SHA1";
labels["TLS1_CK_ECDH_RSA_WITH_NULL_SHA"]           = "n/a|TLSv1|Kx=ECDH|Au=RSA|Enc=None|Mac=SHA1";
labels["TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA"]        = "n/a|TLSv1|Kx=ECDH|Au=RSA|Enc=RC4(128)|Mac=SHA1";
labels["TLS1_CK_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"]   = "n/a|TLSv1|Kx=ECDH|Au=RSA|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA"]    = "n/a|TLSv1|Kx=ECDH|Au=RSA|Enc=AES(128)|Mac=SHA1";
labels["TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA"]    = "n/a|TLSv1|Kx=ECDH|Au=RSA|Enc=AES(256)|Mac=SHA1";
labels["TLS1_CK_ECDHE_RSA_WITH_NULL_SHA"]          = "n/a|TLSv1|Kx=ECDH|Au=RSA|Enc=None|Mac=SHA1";
labels["TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA"]       = "n/a|TLSv1|Kx=ECDH|Au=RSA|Enc=RC4(128)|Mac=SHA1";
labels["TLS1_CK_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"]  = "n/a|TLSv1|Kx=ECDH|Au=RSA|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA"]   = "n/a|TLSv1|Kx=ECDH|Au=RSA|Enc=AES(128)|Mac=SHA1";
labels["TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA"]   = "n/a|TLSv1|Kx=ECDH|Au=RSA|Enc=AES(256)|Mac=SHA1";
labels["TLS1_CK_ECDH_anon_NULL_WITH_SHA"]          = "n/a|TLSv1|Kx=ECDH|Au=None|Enc=None|Mac=SHA1";
labels["TLS1_CK_ECDH_anon_WITH_RC4_128_SHA"]       = "n/a|TLSv1|Kx=ECDH|Au=None|Enc=RC4(128)|Mac=SHA1";
labels["TLS1_CK_ECDH_anon_WITH_3DES_EDE_CBC_SHA"]  = "n/a|TLSv1|Kx=ECDH|Au=None|Enc=3DES(168)|Mac=SHA1";
labels["TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA"]   = "n/a|TLSv1|Kx=ECDH|Au=None|Enc=AES(128)|Mac=SHA1";
labels["TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA"]   = "n/a|TLSv1|Kx=ECDH|Au=None|Enc=AES(256)|Mac=SHA1";


# Determine which ciphers are supported.
supported_ciphers = make_array();

foreach encaps (make_list(ENCAPS_SSLv2, ENCAPS_SSLv3, ENCAPS_TLSv1))
{
  # See if the server supports this type of SSL by sending a client hello
  # with every possible cipher spec.
  if (encaps == ENCAPS_SSLv2)      ssl_ver = raw_string(0x00, 0x02);
  else if (encaps == ENCAPS_SSLv3) ssl_ver = raw_string(0x03, 0x00);
  else if (encaps == ENCAPS_TLSv1) ssl_ver = raw_string(0x03, 0x01);

  cipherspec = "";
  foreach cipher (sort(keys(ciphers)))
  {
    if (
      (encaps == ENCAPS_SSLv2 && "SSL2_" >< cipher) ||
      (encaps == ENCAPS_SSLv3 && "SSL3_" >< cipher) ||
      (encaps == ENCAPS_TLSv1 && "TLS1_" >< cipher)
    ) cipherspec += ciphers[cipher];
  }

  helo = client_hello(
    version    : ssl_ver,
    cipherspec : cipherspec,
    v2hello    : FALSE
  );

  soc = open_sock_tcp(port, transport:ENCAPS_IP);
  if (soc)
  {
    send(socket:soc, data:helo);
    res = recv(socket:soc, length:16);
    close(soc);

    if (
      strlen(res) > 6 &&
      (
        (
          encaps == ENCAPS_SSLv2 &&
          substr(res, 5, 6) == ssl_ver &&          # version matches and...
          getbyte(blob:res, pos:2) == 4            #   a server hello
        ) ||
        (
          encaps == ENCAPS_SSLv3 &&
          substr(res, 1, 2) == ssl_ver &&          # version matches and...
          getbyte(blob:res, pos:0) == 22           #   a handshake
        ) ||
        (
          encaps == ENCAPS_TLSv1 &&
          substr(res, 1, 2) == ssl_ver &&          # version matches and...
          getbyte(blob:res, pos:0) == 22           #   a handshake
        )
      )
    )
    {
      # Iterate over each cipher.
      foreach cipher (sort(keys(ciphers)))
      {
        # If the cipher corresponds to the supported SSL type...
        if (
          (encaps == ENCAPS_SSLv2 && "SSL2_" >< cipher) ||
          (encaps == ENCAPS_SSLv3 && "SSL3_" >< cipher) ||
          (encaps == ENCAPS_TLSv1 && "TLS1_" >< cipher)
        )
        {
          helo = client_hello(
            version    : ssl_ver,
            cipherspec : ciphers[cipher],
            cspeclen   : mkword(strlen(ciphers[cipher])),
            v2hello    : FALSE
          );

          soc = open_sock_tcp(port, transport:ENCAPS_IP);
          if (soc)
          {
            send(socket:soc, data:helo);
            res = recv(socket:soc, length:16);
            if (
              strlen(res) > 10 &&
              (
                (
                  encaps == ENCAPS_SSLv2 &&
                  substr(res, 5, 6) == ssl_ver &&          # version matches and...
                  getbyte(blob:res, pos:2) == 4 &&         # a server hello and
                  getword(blob:res, pos:9) == 3            # cipher spec length == 3
                ) ||
                (
                  encaps == ENCAPS_SSLv3 &&
                  substr(res, 9, 10) == ssl_ver &&
                  getbyte(blob:res, pos:5) == 2
                ) ||
                (
                  encaps == ENCAPS_TLSv1 &&
                  substr(res, 1, 2) == ssl_ver &&
                  getbyte(blob:res, pos:0) == 22
                )
              )
            ) supported_ciphers[cipher]++;
            close(soc);
          }
        }
      }
    }
  }
}


# Classify supported ciphers by strength.
reports = NULL;
if ( isnull(supported_ciphers) ) exit(0);
foreach cipher (sort(keys(supported_ciphers)))
{
  report = "";

  if (!strlen(labels[cipher]))
  {
    cat = max_strength;
    reports[cat] += "    " + cipher + '\n';
  }
  else
  {
    label = labels[cipher];
    if (label =~ "\|export") cat = EXPORT_STRENGTH;
    else if (label =~ "Enc=None") cat = NULL_STRENGTH;
    else if (label =~ "Enc=AES") cat = HIGH_STRENGTH;
    else 
    {
      pat = ".*Enc=[^|]+\(([0-9]+)\).*";
      if (ereg(pattern:pat, string:label))
      {
        bits = ereg_replace(pattern:pat, replace:"\1", string:label);
        nbits = int(bits);
        if (nbits == 0) cat = NULL_STRENGTH;
        else if (nbits < 128) cat = LOW_STRENGTH;
        else if (nbits == 128) cat = MEDIUM_STRENGTH;
        else if (nbits > 128) cat = HIGH_STRENGTH;
      }
      else cat = max_strength;
    }

    fields = split(label, sep:"|", keep:0);
    if (!egrep(pattern:string("^ +", fields[1]), string:reports[cat]))
      reports[cat] += "    " + fields[1] + '\n';

    i = 0;
    foreach f (fields)
    {
      if (i == 0) max = 25;
      else if (i == 2) max = 12;
      else if (i == 4) max = 15;
      else max = 9;
      if (i != 1)
        report += f + crap(data:" ", length:max-strlen(f)) + "  ";
      i++;
    }
    reports[cat] += "      " + report + '\n';
  }
}


# Generate report.
info = "";
foreach cat (sort(keys(reports)))
  info += "  " + labels[cat] + '\n'
                 + reports[cat] + '\n';
if (!info) exit(0);
info += "The fields above are :" + '\n' +
        '\n' +
        "  {OpenSSL ciphername}" + '\n' +
        "  Kx={key exchange}" + '\n' +
        "  Au={authentication}" + '\n' +
        "  Enc={symmetric encryption method}" + '\n' +
        "  Mac={message authentication code}" + '\n' +
        "  {export flag}" + '\n';


# Issue report.
if (reports[NULL_STRENGTH] || reports[LOW_STRENGTH])
{
  report = string(
    desc_weak,
    "\n\n",
    "Plugin output :\n",
    "\n",
    "Here is a list of the SSL ciphers supported by the remote server :\n",
    "\n",
    info
  );

  security_note(port:port, data:report);
}
else 
{
  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    "Here is a list of the SSL ciphers supported by the remote server :\n",
    "\n",
    info
  );
  security_note(port:port, data:report);
}
