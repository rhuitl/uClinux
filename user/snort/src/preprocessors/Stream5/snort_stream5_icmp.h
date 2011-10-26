#ifndef STREAM5_ICMP_H_
#define STREAM5_ICMP_H_

void Stream5CleanIcmp();
void Stream5InitIcmp();
int Stream5VerifyUdpConfig();
int Stream5ProcessIcmp(Packet *p);
void IcmpUpdateDirection(Stream5LWSession *ssn, char dir,
                        u_int32_t ip, u_int16_t port);

#endif /* STREAM5_ICMP_H_ */
