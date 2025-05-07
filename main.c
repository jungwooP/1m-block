
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define DETAIL_OUTPUT 1
// 1 : Print Packet Infomation, 0 : Only Packet ID 

char* host;

const char* methods[] = { "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};
const int n_methods = sizeof(methods) / sizeof(methods[0]);

void usage() {
    printf("syntax : netfilter-test <host>\n");
    printf("sample : netfilter-test test.gilgil.net\n");
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}


/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t mark, ifi, uid, gid;
	int ret;
	unsigned char *data, *secdata;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);

#if DETAIL_OUTPUT
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
#endif

	}

#if DETAIL_OUTPUT
	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	if (nfq_get_uid(tb, &uid))
		printf("uid=%u ", uid);

	if (nfq_get_gid(tb, &gid))
		printf("gid=%u ", gid);

	ret = nfq_get_secctx(tb, &secdata);
	if (ret > 0)
		printf("secctx=\"%.*s\" ", ret, secdata);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		printf("\n");
		dump(data, ret);
		printf("payload_len=%d ", ret);
    }
	fputc('\n', stdout);
#endif
	return id;
}
	
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    uint32_t id = print_pkt(nfa);
    unsigned char *payload;
    int payload_len = nfq_get_payload(nfa, &payload);
	// IP header parsing 
    if (payload_len >= 0) {
        struct iphdr *iph = (struct iphdr *)payload;
        if (iph->protocol == IPPROTO_TCP) {
            int ip_hdr_len = iph->ihl * 4;
			// TCP header parsing 
            if (payload_len > ip_hdr_len) {
                struct tcphdr *tcph = (struct tcphdr *)(payload + ip_hdr_len);
                int tcp_hdr_len = tcph->doff * 4;
				// HTTP 데이터 위치 파악 
                int hdrs_len = ip_hdr_len + tcp_hdr_len;
                if (payload_len > hdrs_len) {
                    char *http = (char *)(payload + hdrs_len);
                    int http_len = payload_len - hdrs_len;
                    // HTTP 요청인지 확인 
					int is_http = 0;
					for (int i = 0; i < n_methods; i++) {
						size_t mlen = strlen(methods[i]);
						// METHOD와 스페이스로 구성되었는지 확인 
						if (http_len >= (int)mlen + 1 && strncmp(http, methods[i], mlen) == 0 && http[mlen] == ' ') {
							is_http = 1;
							break;
						}
					}
					if (is_http){
                        // Host: 헤더 찾기
                        char *h = strcasestr(http, "\r\nHost:");
                        if (h) {
                            h += 7; // skip "\r\nHost:"
                            // 공백 제거
                            while (*h == ' ') h++;
                            char *eol = strstr(h, "\r\n");
                            if (eol) {
                                int len = eol - h;
                                // host 문자열과 길이/내용 비교
                                if (len == (int)strlen(host) &&
                                    strncasecmp(h, host, len) == 0) {
                                    // 유해 사이트: DROP
									printf("  => %s - Blocked !\n",host);
                                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                                }
								// 그외 사이트: ACCEPT - 중요한 것은 아니어서 'Note'라고만 명시함 (없어도 과제 수행과 무관)
                                /*
								printf("  => [Note] ");  
								for (char *p = h; *p && *p != '\r' && *p != '\n'; ++p) {
    								char c = *p;
									if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
									putchar(c);
								}
								printf(" - Accepted !\n");
                                */
                            }
                        }
					}
                }
            }
        }
    }
    // 그 외 경우는 통과
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}



int main(int argc, char **argv)
{
	if (argc != 2) {
        usage();
        return EXIT_FAILURE;
    }
	host = argv[1];

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	int i = 0; 
	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("%dth packet received\n", ++i);
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

