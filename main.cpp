#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <chrono>
#include <string>
#include <fstream>
#include <unordered_set>
#include <algorithm>
#include <libnetfilter_queue/libnetfilter_queue.h>

// 사용법 출력 함수
void usage() {
    printf("syntax : 1m-block <site list file>\n");
    printf("sample : 1m-block top-1m.csv\n");
}

// 차단할 도메인을 저장할 전역 해시테이블
static std::unordered_set<std::string> bad_domains;

// 현재 프로세스의 RSS 메모리(MB) 가져오기
static double get_rss_mb() {
    std::ifstream ifs("/proc/self/status");
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
            auto kb = std::stoul(line.substr(6));
            return kb / 1024.0;
        }
    }
    return 0.0;
}

// 도메인 리스트 파일(CSV 또는 TXT) 로드
// load_time에 로딩 시간(초) 저장
static bool load_domains(const char *fname, double &load_time) {
    std::ifstream ifs(fname);
    if (!ifs) { perror("failed to open domain list"); return false; }
    bad_domains.reserve(1000000);

    auto t0 = std::chrono::steady_clock::now();
    size_t cnt = 0;
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        auto pos = line.find(',');
        std::string dom = (pos != std::string::npos ? line.substr(pos+1) : line);
        // 앞뒤 공백 제거
        while (!dom.empty() && std::isspace((unsigned char)dom.back()))
            dom.pop_back();
        // 소문자 변환
        std::transform(dom.begin(), dom.end(), dom.begin(), ::tolower);
        // "www." 접두어 제거
        if (dom.rfind("www.",0)==0) dom.erase(0,4);
        if (!dom.empty()) {
            bad_domains.insert(std::move(dom));
            ++cnt;
        }
    }
    auto t1 = std::chrono::steady_clock::now();
    load_time = std::chrono::duration<double>(t1 - t0).count();
    printf("Loaded %zu domains in %.3f seconds\n", cnt, load_time);
    printf("Memory after load: %.2f MB RSS\n", get_rss_mb());
    return true;
}

// 디버그용: 패킷 ID 출력
static uint32_t print_pkt(struct nfq_data *tb) {
    if (auto ph = nfq_get_msg_packet_hdr(tb)) {
        uint32_t id = ntohl(ph->packet_id);
        //printf("[pkt id=%u]\n", id);
        return id;
    }
    return 0;
}

// HTTP 패킷에서 Host 헤더 파싱
static bool parse_http_host(unsigned char *pkt, int pkt_len, char *host_out) {
    if (pkt_len < (int)sizeof(iphdr)) return false;
    auto iph = (iphdr*)pkt;
    if (iph->protocol != IPPROTO_TCP) return false;
    int ihl = iph->ihl*4;
    if (pkt_len < ihl + (int)sizeof(tcphdr)) return false;

    auto tcph = (tcphdr*)(pkt + ihl);
    int thl = tcph->doff*4;
    int offset = ihl + thl;
    if (pkt_len <= offset + 8) return false;

    char *http = (char*)(pkt + offset);
    int len = pkt_len - offset;

    // 요청 라인 건너뛰기
    char *nl = (char*)memchr(http, '\n', len);
    if (!nl) return false;
    int used = (nl+1) - http;
    http += used; len -= used;

    // 헤더 라인 순회
    while (len > 0) {
        // 빈 줄이면 헤더 끝
        if ((len>=2 && http[0]=='\r' && http[1]=='\n') ||
            (len>=1 && http[0]=='\n'))
            break;
        char *eol = (char*)memchr(http, '\n', len);
        int linelen = eol ? (eol - http) : len;
        char *colon = (char*)memchr(http, ':', linelen);
        if (colon) {
            int keylen = colon - http;
            if (keylen==4 && strncasecmp(http,"Host",4)==0) {
                char *val = colon+1;
                int vlen = linelen - (keylen+1);
                // 값의 앞뒤 공백 제거
                while (vlen>0 && std::isspace((unsigned char)*val)) { ++val; --vlen; }
                while (vlen>0 && std::isspace((unsigned char)val[vlen-1])) --vlen;
                int copylen = std::min(vlen, 255);
                memcpy(host_out, val, copylen);
                host_out[copylen]=0;
                // 소문자 변환 및 "www." 제거
                for (int i=0; host_out[i]; ++i)
                    host_out[i] = tolower((unsigned char)host_out[i]);
                if (strncmp(host_out,"www.",4)==0)
                    memmove(host_out, host_out+4, strlen(host_out+4)+1);
                return true;
            }
        }
        if (!eol) break;
        used = (eol+1) - http;
        http += used; len -= used;
    }
    return false;
}

// NFQUEUE 콜백: 도메인 검사 후 차단 또는 허용
static int cb(struct nfq_q_handle *qh, struct nfgenmsg*, struct nfq_data *nfa, void*) {
    uint32_t id = print_pkt(nfa);

    unsigned char *pkt;
    int len = nfq_get_payload(nfa, &pkt);
    if (len <= 0)
        return nfq_set_verdict(qh,id,NF_ACCEPT,0,nullptr);

    char host[256];
    if (parse_http_host(pkt,len,host)) {
        auto t0 = std::chrono::steady_clock::now();
        bool blocked = bad_domains.count(host);
        auto t1 = std::chrono::steady_clock::now();
        double dt = std::chrono::duration<double>(t1 - t0).count();

        if (blocked) {
            printf(" [-] Blocked domain: %s (found in %.6f seconds)\n", host, dt);
            return nfq_set_verdict(qh,id,NF_DROP,0,nullptr);
        } else {
            //printf(" [+] %s not blocked (search took %.6f seconds)\n", host, dt);
        }
    }
    return nfq_set_verdict(qh,id,NF_ACCEPT,0,nullptr);
}

int main(int argc, char**argv) {
    if (argc!=2) {
        usage();
        return EXIT_FAILURE;
    }
    double load_time = 0;
    if (!load_domains(argv[1], load_time))
        return EXIT_FAILURE;

    // NFQUEUE 초기화 및 바인딩
    auto h = nfq_open();
    if (!h) { perror("nfq_open"); return EXIT_FAILURE; }
    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET)<0) { perror("nfq_bind_pf"); return EXIT_FAILURE; }

    auto qh = nfq_create_queue(h, 0, &cb, nullptr);
    if (!qh) { perror("nfq_create_queue"); return EXIT_FAILURE; }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff)<0) {
        perror("nfq_set_mode"); return EXIT_FAILURE;
    }

    // iptables 설정 예시 안내
    printf("Guideline: Redirect HTTP(port 80) only to NFQUEUE #0:\n");
    printf("  sudo iptables -F\n");
    printf("  sudo iptables -I OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0\n");
    printf("  sudo iptables -I INPUT  -p tcp --sport 80 -j NFQUEUE --queue-num 0\n");

    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned));
    while (true) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv>=0) { nfq_handle_packet(h, buf, rv); continue; }
        if (rv<0 && errno==ENOBUFS) {
            fprintf(stderr,"WARNING: losing packets\n");
            continue;
        }
        perror("recv");
        break;
    }

    nfq_destroy_queue(qh);
    nfq_unbind_pf(h,AF_INET);
    nfq_close(h);
    return 0;
}

