// slow_peripheral.cpp
#include <iostream>
#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
using namespace std;

static const int HDR_SIZE = 32, DATA_MAX = 1440;
static const uint32_t FLAG_C = 1<<4, FLAG_R = 1<<3, FLAG_ACK = 1<<2, FLAG_AR = 1<<1;

struct SID { uint8_t b[16]; static SID nil(){ SID s{}; memset(s.b,0,16); return s; } };

struct Header {
    SID sid;
    uint32_t sf;    // STTL (upper 27 bits) + flags (lower 5 bits)
    uint32_t seq, ack;
    uint16_t wnd;
    uint8_t fid, fo;
    Header(): sid(SID::nil()), sf(0), seq(0), ack(0), wnd(0), fid(0), fo(0) {}
};

void pack32(uint32_t v, uint8_t* p){ for(int i=0;i<4;i++){ p[i]=v&0xFF; v>>=8; } }
uint32_t unpack32(const uint8_t* p){ uint32_t v=0; for(int i=0;i<4;i++) v |= p[i]<<(i*8); return v; }
void pack16(uint16_t v, uint8_t* p){ for(int i=0;i<2;i++){ p[i]=v&0xFF; v>>=8; } }
uint16_t unpack16(const uint8_t* p){ uint16_t v=0; for(int i=0;i<2;i++) v |= p[i]<<(i*8); return v; }

void serialize(const Header& h, uint8_t* buf) {
    memcpy(buf, h.sid.b, 16);
    pack32(h.sf,        buf+16);
    pack32(h.seq,       buf+20);
    pack32(h.ack,       buf+24);
    pack16(h.wnd,       buf+28);
    buf[30] = h.fid;
    buf[31] = h.fo;
}

void deserialize(Header& h, const uint8_t* buf) {
    memcpy(h.sid.b, buf, 16);
    h.sf  = unpack32(buf+16);
    h.seq = unpack32(buf+20);
    h.ack = unpack32(buf+24);
    h.wnd = unpack16(buf+28);
    h.fid = buf[30];
    h.fo  = buf[31];
}

class UDPPeripheral {
    int fd;
    sockaddr_in srv;
    Header lastHdr, prevHdr;
    bool active = false, hasPrev = false;
    uint32_t nextSeq = 0, lastCentralSeq = 0;
public:
    UDPPeripheral(): fd(-1) { }

    ~UDPPeripheral() { if (fd>=0) close(fd); }

    bool init(const char* host, int port) {
        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return false;
        hostent* he = gethostbyname(host);
        if (!he) return false;
        memset(&srv, 0, sizeof(srv));
        srv.sin_family = AF_INET;
        memcpy(&srv.sin_addr, he->h_addr, he->h_length);
        srv.sin_port = htons(port);
        timeval tv{5,0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        return true;
    }

    bool connect() {
        Header h; h.seq = nextSeq++; h.wnd = 5*DATA_MAX; h.sf |= FLAG_C;
        uint8_t buf[HDR_SIZE]; serialize(h, buf);
        if (sendto(fd, buf, HDR_SIZE, 0, (sockaddr*)&srv, sizeof(srv))<HDR_SIZE) return false;
        uint8_t rbuf[HDR_SIZE+DATA_MAX];
        sockaddr_in sa; socklen_t sl=sizeof(sa);
        if (recvfrom(fd, rbuf, sizeof(rbuf), 0, (sockaddr*)&sa, &sl)<HDR_SIZE) return false;
        Header r; deserialize(r, rbuf);
        if (r.ack!=0 || !(r.sf&FLAG_AR)) return false;
        prevHdr = r; hasPrev = true; active = true; lastCentralSeq = r.seq;
        return true;
    }

    bool disconnect() {
        if (!active) return false;
        Header h = prevHdr; h.seq = nextSeq++; h.ack = lastCentralSeq;
        h.sf = (h.sf & ~0x1F); // clear flags for disconnect
        uint8_t buf[HDR_SIZE]; serialize(h, buf);
        if (sendto(fd, buf, HDR_SIZE, 0, (sockaddr*)&srv, sizeof(srv))<HDR_SIZE) return false;
        active = false; return true;
    }

    bool sendData(const string& msg) {
        if (!active || msg.size()>DATA_MAX) return false;
        Header h = prevHdr; h.seq = nextSeq++; h.ack = lastCentralSeq; h.wnd = 5*DATA_MAX;
        uint8_t buf[HDR_SIZE+DATA_MAX]; serialize(h, buf);
        memcpy(buf+HDR_SIZE, msg.data(), msg.size());
        if (sendto(fd, buf, HDR_SIZE+msg.size(), 0, (sockaddr*)&srv, sizeof(srv))<0) return false;
        uint8_t rbuf[HDR_SIZE+DATA_MAX];
        sockaddr_in sa; socklen_t sl=sizeof(sa);
        if (recvfrom(fd, rbuf, sizeof(rbuf), 0, (sockaddr*)&sa, &sl)<HDR_SIZE) return false;
        Header r; deserialize(r, rbuf);
        if (!(r.sf & FLAG_ACK)) return false;
        lastCentralSeq = r.seq; prevHdr = r;
        return true;
    }

    void storeSession() {
        if (active) { prevHdr = lastHdr; hasPrev = true; }
    }

    bool canRevive() const { return hasPrev; }

    bool zeroWay(const string& msg) {
        if (active || !hasPrev || msg.size()>DATA_MAX) return false;
        Header h = prevHdr; h.seq = nextSeq++; h.ack = lastCentralSeq; h.sf |= FLAG_R;
        uint8_t buf[HDR_SIZE+DATA_MAX]; serialize(h, buf);
        memcpy(buf+HDR_SIZE, msg.data(), msg.size());
        if (sendto(fd, buf, HDR_SIZE+msg.size(), 0, (sockaddr*)&srv, sizeof(srv))<0) return false;
        uint8_t rbuf[HDR_SIZE+DATA_MAX];
        sockaddr_in sa; socklen_t sl=sizeof(sa);
        if (recvfrom(fd, rbuf, sizeof(rbuf), 0, (sockaddr*)&sa, &sl)<HDR_SIZE) return false;
        Header r; deserialize(r, rbuf);
        if (!(r.sf & FLAG_ACK) || !(r.sf & FLAG_AR)) return false;
        active = true; prevHdr = r; lastCentralSeq = r.seq;
        return true;
    }
};

int main(){
    UDPPeripheral p;
    if(!p.init("slow.gmelodie.com",7033)){ cerr<<"Network init failed\n"; return 1; }
    if(!p.connect()){ cerr<<"Connect failed\n"; return 1; }

    string cmd;
    while(true){
        cout<<"Enter 'data', 'disconnect', 'revive' or 'end': ";
        if(!(cin>>cmd)) break;
        if(cmd=="data"){
            cin.ignore();
            string m; getline(cin,m);
            cout<<(p.sendData(m)?"Sent\n":"Send error\n");
        }
        else if(cmd=="disconnect"){
            cout<<(p.disconnect()?"Disconnected\n":"Disconnect error\n");
        }
        else if(cmd=="revive"){
            if(p.canRevive()){
                cin.ignore();
                string m; getline(cin,m);
                cout<<(p.zeroWay(m)?"Revived\n":"Revive failed\n");
            } else cout<<"No previous session\n";
        }
        else if(cmd=="end"){
            p.disconnect();
            break;
        }
    }
    return 0;
}
