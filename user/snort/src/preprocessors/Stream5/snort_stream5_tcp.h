#ifndef STREAM5_TCP_H_
#define STREAM5_TCP_H_

void Stream5CleanTcp();
void Stream5InitTcp();
int Stream5VerifyTcpConfig();
void Stream5TcpPolicyInit(u_char *);
int Stream5ProcessTcp(Packet *p);
int Stream5FlushListener(Packet *p, Stream5LWSession *lwssn);
int Stream5FlushTalker(Packet *p, Stream5LWSession *lwssn);
int Stream5FlushClient(Packet *p, Stream5LWSession *lwssn);
int Stream5FlushServer(Packet *p, Stream5LWSession *lwssn);
void TcpUpdateDirection(Stream5LWSession *ssn, char dir,
                        u_int32_t ip, u_int16_t port);
void Stream5TcpBlockPacket(Packet *p);
Stream5LWSession *GetLWTcpSession(SessionKey *key);
int GetTcpRebuiltPackets(Packet *p, Stream5LWSession *ssn,
        PacketIterator callback, void *userdata);
int Stream5AddSessionAlertTcp(Stream5LWSession *lwssn, Packet *p, u_int32_t gid, u_int32_t sid);
int Stream5CheckSessionAlertTcp(Stream5LWSession *lwssn, Packet *p, u_int32_t gid, u_int32_t sid);
char Stream5GetReassemblyDirectionTcp(Stream5LWSession *lwssn);
char Stream5SetReassemblyTcp(Stream5LWSession *lwssn, u_int8_t flush_policy, char dir, char flags);
char Stream5GetReassemblyFlushPolicyTcp(Stream5LWSession *lwssn, char dir);
char Stream5IsStreamSequencedTcp(Stream5LWSession *lwssn, char dir);
#endif /* STREAM5_TCP_H_ */
