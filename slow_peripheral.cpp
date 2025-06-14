//  ────────────────────────────────────────────────────────────────────────────────
//  SLOW Protocol ‒ Peripheral (versão COMPLETA corrigida)
//  • Flags remapeadas para que CONNECT gere 0x10000000 (10 00 00 00 em hex)
//  • Campo STTL+FLAGS agora escrito/lido em endianness de rede (big‑endian)
//  • Restante da lógica mantida do exemplo anterior
//  ────────────────────────────────────────────────────────────────────────────────

#include <iostream>
#include <vector>
#include <map>git
#include <queue>
#include <string>
#include <cstring>
#include <random>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

// ──────────────────────────── Constantes gerais ────────────────────────────
#define SLOW_PORT        7033
#define MAX_PACKET_SIZE  1472
#define MAX_DATA_SIZE    1440
#define UUID_SIZE        16

// ─── FLAGS (5 bits → irão para os bits 31‑27 após «<<27») ───
//  bit  0  = REVIVE           (vai parar no bit‑27)
//  bit  1  = CONNECT          (vai parar no bit‑28)
//  bit  2  = ACK              (bit‑29)
//  bit  3  = ACCEPT/REJECT    (bit‑30)
//  bit  4  = MORE_BITS        (bit‑31)
#define FLAG_REVIVE         0x01
#define FLAG_CONNECT        0x02
#define FLAG_ACK            0x04
#define FLAG_ACCEPT_REJECT  0x08
#define FLAG_MORE_BITS      0x10

// UUID v8 (RFC‑9562)
#define UUID_VERSION_8        0x8
#define UUID_VARIANT_RFC4122  0x2

// ───────────────────── Estruturas internas do protocolo ────────────────────
struct SlowPacket {
    uint8_t  sid[16];            // Session‑ID
    uint32_t sttl;               // 27 bits (armazenado em 32 para facilitar)
    uint8_t  flags;              // 5 bits (antes de <<27)
    uint32_t seqnum;
    uint32_t acknum;
    uint16_t window;
    uint8_t  fid;
    uint8_t  fo;
    uint8_t  data[MAX_DATA_SIZE];
    uint16_t data_len;           // somente uso interno
};

struct FragmentBuffer {
    std::map<uint8_t, std::vector<uint8_t>> fragments; // fo → dados
    bool   complete;
    uint8_t expected_fragments;
    FragmentBuffer() : complete(false), expected_fragments(0) {}
};

// ───────────────────────────── Classe principal ────────────────────────────
class SlowPeripheral {
private:
    // — estado de sessão / conexão —
    int sock_fd;
    struct sockaddr_in central_addr{};

    uint8_t  session_id[16]{};
    uint32_t next_seqnum{1};
    uint32_t last_acknum{0};
    uint16_t window_size{8192};
    uint32_t session_ttl{0};

    bool connected{false};
    bool session_active{false};

    // — controle de janela deslizante e retransmissão —
    std::queue<SlowPacket>             send_queue;
    std::map<uint32_t, SlowPacket>     unacked_packets; // seq → pkt
    uint16_t  remote_window{0};
    uint32_t  last_acked_seqnum{0};

    // — fragmentação —
    std::map<uint8_t, FragmentBuffer> fragment_buffers; // fid → buffer
    uint8_t next_fid{1};

    // — sincronização e recepção —
    std::mutex              state_mutex;
    std::condition_variable ack_cv;
    std::thread             receiver_thread;
    bool running{false};

    // — buffer de recepção —
    std::vector<uint8_t> receive_buffer;
    static const size_t  BUFFER_SIZE = 8192;

public:
    // ──────────────── Construtor / Destrutor ────────────────
    SlowPeripheral() {
        receive_buffer.resize(BUFFER_SIZE);
        memset(session_id, 0, 16);
    }

    ~SlowPeripheral() {
        disconnect();
        cleanup();
    }

    // ──────────────── Utilidades de UUID ────────────────
    static void generate_uuid_v8(uint8_t* uuid) {
        std::random_device rd; std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        for (int i = 0; i < 16; ++i) uuid[i] = dis(gen);
        uuid[6] = (uuid[6] & 0x0F) | (UUID_VERSION_8 << 4);
        uuid[8] = (uuid[8] & 0x3F) | (UUID_VARIANT_RFC4122 << 6);
    }
    static void generate_nil_uuid(uint8_t* uuid) { memset(uuid, 0, 16); }

    // ──────────────── DNS/Socket Init ────────────────
    std::string resolve_hostname(const std::string& h) {
        struct addrinfo hints{}, *res;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(h.c_str(), nullptr, &hints, &res) != 0) return "";
        auto* addr_in = reinterpret_cast<sockaddr_in*>(res->ai_addr);
        std::string ip = inet_ntoa(addr_in->sin_addr);
        freeaddrinfo(res); return ip;
    }

    bool init(const std::string& host) {
        std::string ip =
            (host.find_first_not_of("0123456789.") == std::string::npos)
                ? host
                : resolve_hostname(host);
        if (ip.empty()) { std::cerr << "resolve failed\n"; return false; }

        sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_fd < 0) { perror("socket"); return false; }

        memset(&central_addr, 0, sizeof(central_addr));
        central_addr.sin_family = AF_INET;
        central_addr.sin_port   = htons(SLOW_PORT);
        if (inet_pton(AF_INET, ip.c_str(), &central_addr.sin_addr) <= 0) {
            std::cerr << "inet_pton failed\n"; return false; }

        running = true;
        receiver_thread = std::thread(&SlowPeripheral::receiver_loop, this);
        return true;
    }

// ─────────────────── (Des)serialização de pacotes ───────────────────
private:
    // ------ Serializar (STTL+FLAGS em big‑endian) ------
    std::vector<uint8_t> serialize_packet(const SlowPacket& pkt) {
        std::vector<uint8_t> buf(32 + pkt.data_len);
        size_t off = 0;

        memcpy(buf.data() + off, pkt.sid, 16); off += 16;

        uint32_t sttl_flags = ((pkt.flags & 0x1F) << 27) | (pkt.sttl & 0x07FFFFFF);
        uint32_t net_sttl_flags = htonl(sttl_flags);
        memcpy(buf.data() + off, &net_sttl_flags, 4); off += 4;

        // seqnum (little‑endian conforme implementação original)
        buf[off++] =  pkt.seqnum        & 0xFF;
        buf[off++] = (pkt.seqnum >> 8 ) & 0xFF;
        buf[off++] = (pkt.seqnum >> 16) & 0xFF;
        buf[off++] = (pkt.seqnum >> 24) & 0xFF;

        buf[off++] =  pkt.acknum        & 0xFF;
        buf[off++] = (pkt.acknum >> 8 ) & 0xFF;
        buf[off++] = (pkt.acknum >> 16) & 0xFF;
        buf[off++] = (pkt.acknum >> 24) & 0xFF;

        buf[off++] =  pkt.window        & 0xFF;
        buf[off++] = (pkt.window >> 8 ) & 0xFF;

        buf[off++] = pkt.fid;
        buf[off++] = pkt.fo;

        if (pkt.data_len)
            memcpy(buf.data() + off, pkt.data, pkt.data_len);

        return buf;
    }

    // ------ Desserializar ------
    SlowPacket deserialize_packet(const std::vector<uint8_t>& buf) {
        SlowPacket p{}; if (buf.size() < 32) return p;
        size_t off = 0;

        memcpy(p.sid, buf.data() + off, 16); off += 16;

        uint32_t net_sttl_flags; memcpy(&net_sttl_flags, buf.data() + off, 4);
        uint32_t sttl_flags = ntohl(net_sttl_flags); off += 4;
        p.flags = (sttl_flags >> 27) & 0x1F;
        p.sttl  =  sttl_flags & 0x07FFFFFF;

        p.seqnum = buf[off] | (buf[off+1] << 8) | (buf[off+2] << 16) | (buf[off+3] << 24); off += 4;
        p.acknum = buf[off] | (buf[off+1] << 8) | (buf[off+2] << 16) | (buf[off+3] << 24); off += 4;
        p.window = buf[off] | (buf[off+1] << 8); off += 2;
        p.fid = buf[off++]; p.fo = buf[off++];
        p.data_len = buf.size() - off;
        if (p.data_len && p.data_len <= MAX_DATA_SIZE)
            memcpy(p.data, buf.data() + off, p.data_len);
        else p.data_len = 0;
        return p;
    }

// ─────────────────────── Envio de pacotes ──────────────────────────
private:
    bool send_packet(const SlowPacket& pkt, bool track_ack = true) {
        auto ser = serialize_packet(pkt);

        std::unique_lock<std::mutex> lk(state_mutex);
        // controle de janela remota (apenas para msgs de dados)
        if (track_ack && pkt.data_len) {
            size_t in_flight = 0;
            for (auto& kv : unacked_packets) in_flight += kv.second.data_len;
            if (in_flight + pkt.data_len > remote_window) {
                ack_cv.wait(lk, [&]{
                    size_t inf = 0; for (auto& kv:unacked_packets) inf += kv.second.data_len;
                    return inf + pkt.data_len <= remote_window; });
            }
        }
        lk.unlock();

        ssize_t s = sendto(sock_fd, ser.data(), ser.size(), 0,
                            (sockaddr*)&central_addr, sizeof(central_addr));
        if (s < 0) { perror("sendto"); return false; }

        lk.lock();
        if (track_ack && pkt.data_len) unacked_packets[pkt.seqnum] = pkt;
        std::cout << "Sent seq=" << pkt.seqnum << " flags=0x" << std::hex << +pkt.flags << std::dec
                  << " len=" << pkt.data_len << '\n';
        return true;
    }

// ─────────────────────── Handshake 3‑way ──────────────────────────
public:
    bool connect_3way() {
        SlowPacket c{}; generate_nil_uuid(c.sid);
        c.sttl = 0; c.flags = FLAG_CONNECT; c.seqnum = 0; c.acknum = 0;
        c.window = window_size; c.fid = 0; c.fo = 0; c.data_len = 0;
        if (!send_packet(c,false)) return false;

        std::unique_lock<std::mutex> lk(state_mutex);
        if (!ack_cv.wait_for(lk, std::chrono::seconds(10), [&]{return connected;})) {
            std::cerr << "handshake timeout\n"; return false; }
        std::cout << "3‑way handshake OK (remote_window=" << remote_window << ")\n";
        return true;
    }

// ─────────────────── Envio de dados com fragmentação ───────────────────
private:
    bool send_data_internal(const std::vector<uint8_t>& d, bool revive=false) {
        if (!connected && !session_active) { std::cerr << "not connected\n"; return false; }
        size_t off=0; uint8_t fid = next_fid++, fo=0;
        while (off < d.size()) {
            std::unique_lock<std::mutex> lk(state_mutex);
            ack_cv.wait(lk,[&]{ size_t inf=0; for(auto&kv:unacked_packets) inf+=kv.second.data_len;
                                return inf < remote_window; });
            size_t in_flight=0; for(auto&kv:unacked_packets) in_flight+=kv.second.data_len;
            size_t space = remote_window>in_flight ? remote_window-in_flight : 0;
            lk.unlock(); if (!space) continue;

            size_t chunk = std::min({space,(size_t)MAX_DATA_SIZE,d.size()-off});
            SlowPacket p{}; memcpy(p.sid,session_id,16); p.sttl=session_ttl;
            p.flags = FLAG_ACK;
            if (revive && off==0) p.flags |= FLAG_REVIVE;
            if (off+chunk < d.size()) p.flags |= FLAG_MORE_BITS;
            p.seqnum=next_seqnum++; p.acknum=last_acknum; p.window=window_size-receive_buffer.size();
            p.fid=fid; p.fo=fo++; memcpy(p.data,&d[off],chunk); p.data_len=chunk;
            if (!send_packet(p)) return false; off+=chunk; revive=false;
        }
        return true;
    }
public:
    bool send_data(const std::string& s) {
        return send_data(std::vector<uint8_t>(s.begin(),s.end())); }
    bool send_data(const std::vector<uint8_t>& v) { return send_data_internal(v); }

// ─────────────────────── Desconectar / 0‑way ──────────────────────────
    bool disconnect() {
        if (!connected && !session_active) return true;
        SlowPacket p{}; memcpy(p.sid,session_id,16); p.sttl=session_ttl;
        p.flags = FLAG_ACK | FLAG_CONNECT | FLAG_REVIVE; // sinaliza disconnect
        p.seqnum=next_seqnum++; p.acknum=last_acknum; p.window=0; p.data_len=0;
        bool ok=send_packet(p,false);
        connected=false; session_active=true;
        std::cout << "Disconnected (sessão preservada)\n";
        return ok;
    }

    bool connect_0way(const std::vector<uint8_t>& d) {
        if (!session_active) { std::cerr << "sem sessão para reviver\n"; return false; }
        return send_data_internal(d,true);
    }

// ─────────────────── Loop de recepção / processamento ───────────────────
private:
    void process_packet(const SlowPacket& p) {
        std::lock_guard<std::mutex> lk(state_mutex);
        std::cout << "Recv seq="<<p.seqnum<<" ack="<<p.acknum<<" flags=0x"<<std::hex<<+p.flags<<std::dec
                  <<" win="<<p.window<<'\n';
        // etapa de Setup (3‑way): qualquer pkt seq!=0 antes de connected
        if (!connected && p.seqnum!=0) {
            memcpy(session_id,p.sid,16); session_ttl=p.sttl; next_seqnum=p.seqnum+1;
            remote_window = p.window? p.window:window_size; connected=true; session_active=true;
            last_acknum=p.seqnum; std::cout<<"Setup accepted\n"; ack_cv.notify_all(); return; }

        // ACKs normais
        if (connected && (p.flags & FLAG_ACK)) {
            if (p.acknum >= last_acked_seqnum) {
                for (auto it=unacked_packets.begin(); it!=unacked_packets.end();) {
                    if (it->first<=p.acknum) it=unacked_packets.erase(it); else ++it; }
                last_acked_seqnum=p.acknum; remote_window=p.window; }
            last_acknum=p.seqnum; ack_cv.notify_all(); }
        // dados (fragmentação simples)
        if (p.data_len) {
            if (p.flags & FLAG_MORE_BITS) fragment_buffers[p.fid].fragments[p.fo]=
                        std::vector<uint8_t>(p.data,p.data+p.data_len);
            else {
                auto &fb=fragment_buffers[p.fid];
                fb.fragments[p.fo]=std::vector<uint8_t>(p.data,p.data+p.data_len);
                fb.complete=true; fb.expected_fragments=p.fo+1;
                std::vector<uint8_t> full;
                for(uint8_t i=0;i<fb.expected_fragments;i++)
                    full.insert(full.end(),fb.fragments[i].begin(),fb.fragments[i].end());
                std::cout<<"Reassembled "<<full.size()<<" bytes\n"; fragment_buffers.erase(p.fid);
            }
        }
    }

    void receiver_loop() {
        uint8_t buf[MAX_PACKET_SIZE]; sockaddr_in from; socklen_t l=sizeof(from);
        while (running) {
            ssize_t r=recvfrom(sock_fd,buf,sizeof(buf),0,(sockaddr*)&from,&l);
            if (r>0) process_packet(deserialize_packet({buf,buf+(size_t)r}));
            else if (r<0 && running) perror("recvfrom");
        }
    }

// ────────────────────────── Utilidades finais ──────────────────────────
public:
    bool has_unacked_data() { std::lock_guard<std::mutex> lk(state_mutex); return !unacked_packets.empty(); }

    void cleanup() {
        running=false; if (receiver_thread.joinable()) receiver_thread.join();
        if (sock_fd>=0) { close(sock_fd); sock_fd=-1; }
    }
};

// ─────────────────────────── Programa de teste ────────────────────────────
int main(int argc,char*argv[]) {
    if (argc<2) { std::cout<<"Usage: "<<argv[0]<<" <central_host>\n"; return 1; }
    SlowPeripheral p; if (!p.init(argv[1])) return 1;
    std::cout<<"-- 3‑way connect...\n"; if (!p.connect_3way()) return 1;

    p.send_data("Hello, SLOW Protocol!");
    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::string big(2000,'A'); big+="END"; p.send_data(big);
    while (p.has_unacked_data()) std::this_thread::sleep_for(std::chrono::milliseconds(100));

    p.disconnect(); std::this_thread::sleep_for(std::chrono::seconds(2));
    p.connect_0way(std::vector<uint8_t>({'O','l','a','!'}));
    std::this_thread::sleep_for(std::chrono::seconds(3));
    return 0;
}
