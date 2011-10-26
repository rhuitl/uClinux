#ifndef NASL_CRYPTO_H
#define NASL_CRYPTO_H

#ifdef HAVE_SSL
tree_cell * nasl_md2(lex_ctxt *);
tree_cell * nasl_md4(lex_ctxt *);
tree_cell * nasl_md5(lex_ctxt *);
tree_cell * nasl_sha(lex_ctxt *);
tree_cell * nasl_sha1(lex_ctxt *);
tree_cell * nasl_ripemd160(lex_ctxt *);
tree_cell * nasl_hmac_md2(lex_ctxt * );
tree_cell * nasl_hmac_md5(lex_ctxt * );
tree_cell * nasl_hmac_sha(lex_ctxt *);
tree_cell * nasl_hmac_sha1(lex_ctxt * );
tree_cell * nasl_hmac_dss(lex_ctxt *);
tree_cell * nasl_hmac_ripemd160(lex_ctxt *);
#endif

#endif
