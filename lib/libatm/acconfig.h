#ifndef _ATM_CONFIG_H
#define _ATM_CONFIG_H

@TOP@

/*
  acconfig.h
*/

/*
  Default config file location for atmsigd
*/
#define ATMSIGD_CONF "/usr/local/etc/atmsigd.conf"

#undef YY_USE_CONST

/*
  The UNI version can be configured at run time. Dynamic is the default. Use the
  explicit version selections only in case of problems.
*/
#undef DYNAMIC_UNI

#undef UNI30

/*
  Note: some UNI 3.0 switches will show really strange behaviour if confronted
	with using 3.1 signaling, so be sure to test your network *very*
	carefully before permanently configuring machines to use UNI 3.1.
*/
#undef UNI31
#undef ALLOW_UNI30

/*
  Some partial support for UNI 4.0 can be enabled by using UNI40
*/
#undef UNI40

/*
  If using UNI40, you can also enable peak cell rate modification as
  specified in Q.2963.1
*/
#undef Q2963_1

/*
  If you're using a Cisco LS100 or LS7010 switch, you should add the following
  line to work around a bug in their point-to-multipoint signaling (it got
  confused when receiving a CALL PROCEEDING, so we don't send it, which of
  course makes our clearing procedure slightly non-conformant):
*/
#undef CISCO

/*
  Some versions of the Thomson Thomflex 5000 won't do any signaling before they
  get a RESTART. Uncomment the next line to enable sending of a RESTART
  whenever SAAL comes up. Note that the RESTART ACKNOWLEDGE sent in response to
  the RESTART will yield a warning, because we don't implement the full RESTART
  state machine.
*/
#undef THOMFLEX

/*
  Use select() instead of poll() with MPOA
*/
#undef BROKEN_POLL

/*
  Use proposed MPOA 1.1 features
*/
#undef MPOA_1_1

@BOTTOM@

#endif

