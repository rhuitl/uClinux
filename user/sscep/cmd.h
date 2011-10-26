
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */

/*
 * Command line options
 * These are defined globally for easy access from all functions.
 * For each command line option 'x', there is int x_flag and
 * char *x_char or int x_num if the option requires parameter.
 */

/* CA certificate */
extern int c_flag;
extern char *c_char;

/* Debug? */
extern int d_flag;

/* CA encryption certificate */
extern int e_flag;
extern char *e_char;

/* Encryption algorithm */
extern char *E_char; 
extern int E_flag;

/* Configuration file */
extern int f_flag;
extern char *f_char;

/* Fingerprint algorithm */
extern char *F_char; 
extern int F_flag;

/* Local certificate  */
extern char *l_char;
extern int l_flag;

/* Local selfsigned certificate  (generated automaticatally) */
extern char *L_char;
extern int L_flag;

/* CA identifier */
extern char *i_char;
extern int i_flag;

/* Private key */
extern char *k_char;
extern int k_flag;

/* Private key of already existing certificate */
extern char *K_char;
extern int K_flag;

/* Request count */
extern int n_flag;
extern int n_num;

/* Already existing certificate (to be renewed) */
extern char *O_char; 
extern int O_flag;

/* Proxy */
extern char *p_char; 
extern int p_flag;

/* GetCrl CRL file */
extern char *r_char; 
extern int r_flag;

/* Resume */
extern int R_flag;

/* Certificate serial number */
extern char *s_char; 
extern int s_flag;

/* Signature algorithm */
extern char *S_char; 
extern int S_flag;

/* Polling interval */
extern int t_num; 
extern int t_flag;

/* Max polling time */
extern int T_num; 
extern int T_flag;

/* URL */
extern int u_flag;
extern char *url_char;

/* Verbose? boolean */
extern int v_flag;

/* GetCert certificate */
extern int w_flag;
extern char *w_char;

/* End of command line options */

