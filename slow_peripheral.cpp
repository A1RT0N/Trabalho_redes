#include <iostream>
#include <iomanip>      
#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <cctype>
#include <algorithm>

using namespace std;

// Cruzao, eu estive aqui 

static const int HDR_SIZE = 32;
static const int DATA_MAX = 1440;
static const uint32_t FLAG_C   = 1 << 4;   
static const uint32_t FLAG_R   = 1 << 3;  
static const uint32_t FLAG_ACK = 1 << 2;   
static const uint32_t FLAG_AR  = 1 << 1;  

// Estrutura para identificador de sessão
struct SID {
    uint8_t b[16];
    static SID nil() {
        SID s{};
        memset(s.b, 0, 16);
        return s;
    }
    
    bool isEqual(const SID& other) const {
        return memcmp(b, other.b, 16) == 0;
    }
};

// Estrutura do cabeçalho do protocolo
struct Header {
    SID sid;         // Session ID
    uint32_t sf;     // STTL (upper 27 bits) + flags (lower 5 bits)
    uint32_t seq;    // Sequence number
    uint32_t ack;    // Acknowledgment number
    uint16_t wnd;    // Window size
    uint8_t fid;     // Fragment ID
    uint8_t fo;      // Fragment offset
    Header() : sid(SID::nil()), sf(0), seq(0), ack(0), wnd(0), fid(0), fo(0) {}
};

// Funções para (de)serialização
void pack32(uint32_t v, uint8_t* p) {
    for (int i = 0; i < 4; i++) {
        p[i] = v & 0xFF;
        v >>= 8;
    }
}

uint32_t unpack32(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        v |= p[i] << (i * 8);
    }
    return v;
}

void pack16(uint16_t v, uint8_t* p) {
    for (int i = 0; i < 2; i++) {
        p[i] = v & 0xFF;
        v >>= 8;
    }
}

uint16_t unpack16(const uint8_t* p) {
    uint16_t v = 0;
    for (int i = 0; i < 2; i++) {
        v |= p[i] << (i * 8);
    }
    return v;
}

void serialize(const Header& h, uint8_t* buf) {
    memcpy(buf, h.sid.b, 16);
    pack32(h.sf,      buf + 16);
    pack32(h.seq,     buf + 20);
    pack32(h.ack,     buf + 24);
    pack16(h.wnd,     buf + 28);
    buf[30] = h.fid;
    buf[31] = h.fo;
}

void deserialize(Header& h, const uint8_t* buf) {
    memcpy(h.sid.b, buf, 16);
    h.sf  = unpack32(buf + 16);
    h.seq = unpack32(buf + 20);
    h.ack = unpack32(buf + 24);
    h.wnd = unpack16(buf + 28);
    h.fid = buf[30];
    h.fo  = buf[31];
}

// Função auxiliar para imprimir todos os campos de Header
void printHeader(const Header& h, const std::string& label) {
    cout << "---- " << label << " ----\n";
    // SID em hex
    cout << "SID: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << setw(2) << setfill('0')
             << static_cast<int>(h.sid.b[i]);
    }
    cout << dec << "\n";

    // Flags (5 bits baixos) e STTL (27 bits altos)
    uint32_t flags =  h.sf       & 0x1F;
    uint32_t sttl  = (h.sf >> 5) & 0x07FFFFFF;
    cout << "Flags: 0x" << hex << flags << dec
         << " (" << flags << ")\n";
    cout << "STTL: "   << sttl   << "\n";

    cout << "SEQNUM: " << h.seq  << "\n";
    cout << "ACKNUM: " << h.ack  << "\n";
    cout << "WINDOW: " << h.wnd  << "\n";
    cout << "FID: "    << static_cast<int>(h.fid) << "\n";
    cout << "FO: "     << static_cast<int>(h.fo)  << "\n\n";
}

// Classe principal do periférico UDP
class UDPPeripheral {
private:
    int fd;
    sockaddr_in srv;
    Header lastHdr, prevHdr;
    bool active = false;
    bool hasPrev = false;
    uint32_t nextSeq = 0;
    uint32_t lastCentralSeq = 0;

public:
    UDPPeripheral() : fd(-1) {}
    ~UDPPeripheral() { if (fd >= 0) close(fd); }

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
        Header h;
        h.seq = nextSeq++;
        h.wnd = 5 * DATA_MAX;
        h.sf |= FLAG_C;

        uint8_t buf[HDR_SIZE];
        serialize(h, buf);

        printHeader(h, "Pacote Enviado (CONNECT)");

        if (sendto(fd, buf, HDR_SIZE, 0, (sockaddr*)&srv, sizeof(srv)) < HDR_SIZE)
            return false;

        uint8_t rbuf[HDR_SIZE + DATA_MAX];
        sockaddr_in sa; socklen_t sl = sizeof(sa);
        if (recvfrom(fd, rbuf, sizeof(rbuf), 0, (sockaddr*)&sa, &sl) < HDR_SIZE)
            return false;

        Header r;
        deserialize(r, rbuf);

        printHeader(r, "Pacote Recebido (CONNECT)");

        if (r.ack != 0 || !(r.sf & FLAG_AR)) return false;
        prevHdr = r;
        hasPrev = true;
        active = true;
        lastCentralSeq = r.seq;
        return true;
    }

    bool disconnect() {
        if (!active) return false;

        // Prepara o pacote de DISCONNECT
        Header h = prevHdr;
        h.seq = nextSeq++;
        h.ack = lastCentralSeq;
        h.sf = (h.sf & ~0x1F) | FLAG_C | FLAG_R;

        uint8_t buf[HDR_SIZE];
        serialize(h, buf);
        printHeader(h, "Pacote Enviado (DISCONNECT)");

        if (sendto(fd, buf, HDR_SIZE, 0, (sockaddr*)&srv, sizeof(srv)) < HDR_SIZE)
            return false;

        // Loop de tentativa de recepção do ACK
        const int MAX_TRIES = 3;
        for (int attempt = 1; attempt <= MAX_TRIES; ++attempt) {
            uint8_t rbuf[HDR_SIZE];
            sockaddr_in sa;
            socklen_t sl = sizeof(sa);

            ssize_t received = recvfrom(fd, rbuf, HDR_SIZE, 0, (sockaddr*)&sa, &sl);
            if (received >= HDR_SIZE) {
                Header r;
                deserialize(r, rbuf);
                printHeader(r, "Pacote Recebido (DISCONNECT)");

                if (r.sf & FLAG_ACK) {
                    // ACK recebido com sucesso
                    active = false;
                    return true;
                } else {
                    cerr << "[AVISO] Pacote sem FLAG_ACK (tentativa " 
                        << attempt << "/" << MAX_TRIES << ")\n";
                }
            } else {
                cerr << "[AVISO] Sem resposta do servidor (tentativa " 
                    << attempt << "/" << MAX_TRIES << ")\n";
            }
        }

        // Desistiu após MAX_TRIES
        cerr << "[ERRO] Não recebeu ACK de DISCONNECT após " 
            << MAX_TRIES << " tentativas. Abortando.\n";
        return false;
    }



    bool sendData(const string& msg) {
        if (!active || msg.size() > DATA_MAX) return false;
        Header h = prevHdr;
        h.seq = nextSeq++;
        h.ack = lastCentralSeq;
        h.wnd = 5 * DATA_MAX;
        h.sf = (h.sf & ~0x1F);  // limpa flags para dados normais

        uint8_t buf[HDR_SIZE + DATA_MAX];
        serialize(h, buf);

        printHeader(h, "Pacote Enviado (DATA)");

        memcpy(buf + HDR_SIZE, msg.data(), msg.size());
        if (sendto(fd, buf, HDR_SIZE + msg.size(), 0, (sockaddr*)&srv, sizeof(srv)) < 0)
            return false;

        uint8_t rbuf[HDR_SIZE + DATA_MAX];
        sockaddr_in sa; socklen_t sl = sizeof(sa);
        if (recvfrom(fd, rbuf, sizeof(rbuf), 0, (sockaddr*)&sa, &sl) < HDR_SIZE)
            return false;

        Header r;
        deserialize(r, rbuf);

        printHeader(r, "Pacote Recebido (DATA)");

        if (!(r.sf & FLAG_ACK)) return false;
        lastCentralSeq = r.seq;
        prevHdr = r;
        return true;
    }

    void storeSession() {
        if (active) {
            lastHdr = prevHdr;
            hasPrev = true;
        }
    }

    bool canRevive() const { return hasPrev; }

    bool zeroWay(const string& msg) {
        if (fd < 0 || !hasPrev) return false;
        
        Header h = lastHdr;  
        h.seq = nextSeq++;
        h.ack = lastCentralSeq;
        h.wnd = 5 * DATA_MAX;
        h.sf = (h.sf & ~0x1F) | FLAG_R;  // Limpa flags e adiciona FLAG_R
        
        uint8_t buf[HDR_SIZE + DATA_MAX];
        serialize(h, buf);

        printHeader(h, "Pacote Enviado (REVIVE)");

        memcpy(buf + HDR_SIZE, msg.data(), msg.size());
        size_t total = HDR_SIZE + msg.size();
        if (sendto(fd, buf, total, 0, (sockaddr*)&srv, sizeof(srv)) < 0)
            return false;
        
        uint8_t rbuf[HDR_SIZE + DATA_MAX];
        sockaddr_in sa; socklen_t sl = sizeof(sa);
        ssize_t received = recvfrom(fd, rbuf, sizeof(rbuf), 0, (sockaddr*)&sa, &sl);
        if (received < HDR_SIZE) return false;
        
        Header r;
        deserialize(r, rbuf);

        printHeader(r, "Pacote Recebido (REVIVE)");

        if ((r.sf & FLAG_ACK) && (r.sf & FLAG_AR) &&
            r.sid.isEqual(lastHdr.sid) && r.ack == h.seq) {
            prevHdr = r;
            active = true;
            lastCentralSeq = r.seq;
            return true;
        }
        
        return false;
    }
};

// Interface de usuário (sem alterações)
void printWelcome() {
    cout << "\n=================================================\n";
    cout << "         UDP Peripheral Client v1.0              \n";
    cout << "=================================================\n";
    cout << "Conectando ao servidor slow.gmelodie.com:7033...\n";
}

void printMenu() {
    cout << "\n┌─────────────────────────────────────────────┐\n";
    cout << "│                  MENU                       │\n";
    cout << "├─────────────────────────────────────────────┤\n";
    cout << "│ 1. data       - Enviar dados                │\n";
    cout << "│ 2. disconnect - Desconectar do servidor     │\n";
    cout << "│ 3. revive     - Reviver sessão anterior     │\n";
    cout << "│ 4. status     - Ver status da conexão       │\n";
    cout << "│ 5. help       - Mostrar ajuda               │\n";
    cout << "│ 6. exit       - Sair do programa            │\n";
    cout << "└─────────────────────────────────────────────┘\n";
}

void printHelp() {
    cout << "\n╔═══════════════════════════════════════════════╗\n";
    cout << "║                     AJUDA                     ║\n";
    cout << "╠═══════════════════════════════════════════════╣\n";
    cout << "║ data: Envia uma mensagem para o servidor      ║\n";
    cout << "║       Você será solicitado a digitar a msg    ║\n";
    cout << "║                                               ║\n";
    cout << "║ disconnect: Encerra a conexão atual           ║\n";
    cout << "║                                               ║\n";
    cout << "║ revive: Restaura uma sessão desconectada      ║\n";
    cout << "║         usando zero-way handshake             ║\n";
    cout << "║                                               ║\n";
    cout << "║ status: Mostra informações da conexão         ║\n";
    cout << "║                                               ║\n";
    cout << "║ exit: Desconecta e sai do programa            ║\n";
    cout << "╚═══════════════════════════════════════════════╝\n";
}

void printStatus(const UDPPeripheral& p, bool connected) {
    cout << "\n┌─────────────────────────────────────────────┐\n";
    cout << "│                  STATUS                     │\n";
    cout << "├─────────────────────────────────────────────┤\n";
    cout << "│ Servidor: slow.gmelodie.com:7033            │\n";
    cout << "│ Conexão:  " << (connected ? "[CONECTADO]   " : "[DESCONECTADO]") << "            │\n";
    cout << "│ Sessão:   " << (p.canRevive() ? "[DISPONÍVEL]  " : "[INDISPONÍVEL]") << "            │\n";
    cout << "└─────────────────────────────────────────────┘\n";
}

string toLowerCase(string str) {
    for (char& c : str) c = tolower(c);
    return str;
}

string getInput(const string& prompt) {
    string input;
    cout << prompt;
    getline(cin, input);
    return input;
}

// Função principal
int main() {
    printWelcome();

    UDPPeripheral p;
    bool connected = false;

    if (!p.init("slow.gmelodie.com", 7033)) {
        cerr << "[ERRO] Falha na inicialização da rede!\n";
        return 1;
    }

    if (!p.connect()) {
        cerr << "[ERRO] Falha na conexão com o servidor!\n";
        return 1;
    }

    connected = true;
    cout << "[OK] Conectado com sucesso!\n";

    string cmd;
    while (true) {
        printMenu();
        cout << "\n> Digite sua opção: ";
        if (!(cin >> cmd)) break;
        cmd = toLowerCase(cmd);
        cout << "\n";

        if (cmd == "1" || cmd == "data") {
            if (!connected) {
                cout << "[ERRO] Não há conexão ativa!\n";
                continue;
            }
            cin.ignore();
            string message = getInput("Digite sua mensagem: ");
            if (message.empty()) {
                cout << "[AVISO] Mensagem vazia não enviada.\n";
                continue;
            }
            cout << "Enviando mensagem...\n";
            if (p.sendData(message)) {
                cout << "[OK] Mensagem enviada com sucesso!\n";
            } else {
                cout << "[ERRO] Erro ao enviar mensagem.\n";
            }

        } else if (cmd == "2" || cmd == "disconnect") {
            if (!connected) {
                cout << "[AVISO] Já está desconectado.\n";
                continue;
            }
            p.storeSession();
            cout << "Desconectando do servidor...\n";
            if (p.disconnect()) {
                cout << "[OK] Desconectado com sucesso!\n";
                connected = false;
            } else {
                cout << "[ERRO] Erro ao desconectar.\n";
            }

        } else if (cmd == "3" || cmd == "revive") {
            if (connected) {
                cout << "[AVISO] Já está conectado. Use 'disconnect' primeiro.\n";
                continue;
            }
            if (!p.canRevive()) {
                cout << "[ERRO] Nenhuma sessão anterior disponível!\n";
                continue;
            }
            cout << "Tentando reviver sessão...\n";
            cin.ignore();
            string reviveMessage = getInput("Digite uma mensagem para enviar com o revive: ");
            if (reviveMessage.empty()) {
                reviveMessage = "Revive test message";
                cout << "[INFO] Usando mensagem padrão: \"" << reviveMessage << "\"\n";
            }
            if (p.zeroWay(reviveMessage)) {
                cout << "[OK] Sessão revivida com sucesso!\n";
                connected = true;
            } else {
                cout << "[ERRO] Falha ao reviver a sessão.\n";
            }

        } else if (cmd == "4" || cmd == "status") {
            printStatus(p, connected);

        } else if (cmd == "5" || cmd == "help") {
            printHelp();

        } else if (cmd == "6" || cmd == "exit" || cmd == "quit" || cmd == "end") {
            if (connected) {
                p.storeSession();
                p.disconnect();
            }
            cout << "Até logo!\n\n";
            break;

        } else {
            cout << "[ERRO] Comando inválido: '" << cmd << "'\n";
            cout << "       Digite 'help' para ver os comandos disponíveis.\n";
        }
    }

    return 0;
}
