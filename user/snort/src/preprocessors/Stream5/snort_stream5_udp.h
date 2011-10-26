#ifndef STREAM5_UDP_H_
#define STREAM5_UDP_H_

void Stream5CleanUdp();
void Stream5InitUdp();
int Stream5VerifyIcmpConfig();
void Stream5UdpPolicyInit(u_char *);
int Stream5ProcessUdp(Packet *p);
void UdpUpdateDirection(Stream5LWSession *ssn, char dir,
                        u_int32_t ip, u_int16_t port);
Stream5LWSession *GetLWUdpSession(SessionKey *key);

#endif /* STREAM5_UDP_H_ */
