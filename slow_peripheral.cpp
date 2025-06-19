// slow_peripheral.cpp (completo com revive implementado)
#include <iostream>
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

// Constantes
static const int HDR_SIZE = 32;
static const int DATA_MAX = 1440;
static const uint32_t FLAG_C   = 1 << 4;   // Connect flag
static const uint32_t FLAG_R   = 1 << 3;   // Revive flag
static const uint32_t FLAG_ACK = 1 << 2;   // Acknowledgment flag
static const uint32_t FLAG_AR  = 1 << 1;   // Accept/Ready flag

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

// Funções para serialização de dados
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

// Serializa o cabeçalho para buffer
void serialize(const Header& h, uint8_t* buf) {
    memcpy(buf, h.sid.b, 16);
    pack32(h.sf, buf + 16);
    pack32(h.seq, buf + 20);
    pack32(h.ack, buf + 24);
    pack16(h.wnd, buf + 28);
    buf[30] = h.fid;
    buf[31] = h.fo;
}

// Deserializa o cabeçalho do buffer
void deserialize(Header& h, const uint8_t* buf) {
    memcpy(h.sid.b, buf, 16);
    h.sf  = unpack32(buf + 16);
    h.seq = unpack32(buf + 20);
    h.ack = unpack32(buf + 24);
    h.wnd = unpack16(buf + 28);
    h.fid = buf[30];
    h.fo  = buf[31];
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
        if (sendto(fd, buf, HDR_SIZE, 0, (sockaddr*)&srv, sizeof(srv)) < HDR_SIZE) return false;
        uint8_t rbuf[HDR_SIZE + DATA_MAX];
        sockaddr_in sa; socklen_t sl = sizeof(sa);
        if (recvfrom(fd, rbuf, sizeof(rbuf), 0, (sockaddr*)&sa, &sl) < HDR_SIZE) return false;
        Header r; deserialize(r, rbuf);
        if (r.ack != 0 || !(r.sf & FLAG_AR)) return false;
        prevHdr = r;
        hasPrev = true;
        active = true;
        lastCentralSeq = r.seq;
        return true;
    }

    bool disconnect() {
        if (!active) return false;
        Header h = prevHdr;
        h.seq = nextSeq++;
        h.ack = lastCentralSeq;
        h.sf = (h.sf & ~0x1F);  // limpa flags
        uint8_t buf[HDR_SIZE]; serialize(h, buf);
        if (sendto(fd, buf, HDR_SIZE, 0, (sockaddr*)&srv, sizeof(srv)) < HDR_SIZE) return false;
        active = false;
        return true;
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
        memcpy(buf + HDR_SIZE, msg.data(), msg.size());
        if (sendto(fd, buf, HDR_SIZE + msg.size(), 0, (sockaddr*)&srv, sizeof(srv)) < 0) return false;
        uint8_t rbuf[HDR_SIZE + DATA_MAX]; sockaddr_in sa; socklen_t sl = sizeof(sa);
        if (recvfrom(fd, rbuf, sizeof(rbuf), 0, (sockaddr*)&sa, &sl) < HDR_SIZE) return false;
        Header r; deserialize(r, rbuf);
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
        
        // Constrói o cabeçalho de revive com dados
        Header h = lastHdr;  // Usa os dados da sessão anterior armazenada
        h.seq = nextSeq++;
        h.ack = lastCentralSeq;
        h.wnd = 5 * DATA_MAX;
        h.sf = (h.sf & ~0x1F) | FLAG_R;  // Limpa flags e adiciona flag R (revive)
        
        // Prepara o buffer com cabeçalho + dados
        uint8_t buf[HDR_SIZE + DATA_MAX];
        serialize(h, buf);
        memcpy(buf + HDR_SIZE, msg.data(), msg.size());
        size_t total = HDR_SIZE + msg.size();
        
        // Envia a requisição de revive com dados
        if (sendto(fd, buf, total, 0, (sockaddr*)&srv, sizeof(srv)) < 0) return false;
        
        // Aguarda resposta ACK+AR
        uint8_t rbuf[HDR_SIZE + DATA_MAX];
        sockaddr_in sa; 
        socklen_t sl = sizeof(sa);
        ssize_t received = recvfrom(fd, rbuf, sizeof(rbuf), 0, (sockaddr*)&sa, &sl);
        
        if (received < HDR_SIZE) return false;
        
        Header r;
        deserialize(r, rbuf);
        
        // Verifica se é um ACK+AR válido para o revive
        if ((r.sf & FLAG_ACK) && (r.sf & FLAG_AR) && 
            r.sid.isEqual(lastHdr.sid) && r.ack == h.seq) {
            
            // Sessão revivida com sucesso
            prevHdr = r;
            active = true;
            lastCentralSeq = r.seq;
            return true;
        }
        
        return false;
    }
};

// Funções auxiliares para interface
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

    // Inicialização
    if (!p.init("slow.gmelodie.com", 7033)) {
        cerr << "[ERRO] Falha na inicialização da rede!\n";
        cerr << "       Verifique sua conexão com a internet.\n";
        return 1;
    }

    if (!p.connect()) {
        cerr << "[ERRO] Falha na conexão com o servidor!\n";
        cerr << "       O servidor pode estar indisponível.\n";
        return 1;
    }

    connected = true;
    cout << "[OK] Conectado com sucesso!\n";

    string cmd;
    while (true) {
        printMenu();
        cout << "\n> Digite sua opção: ";

        if (!(cin >> cmd)) {
            cout << "\n[ERRO] Erro na leitura da entrada. Encerrando...\n";
            break;
        }

        cmd = toLowerCase(cmd);
        cout << "\n";

        if (cmd == "1" || cmd == "data") {
            if (!connected) {
                cout << "[ERRO] Não há conexão ativa!\n";
                cout << "       Use 'revive' para restaurar uma sessão anterior.\n";
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

            // Antes de desconectar, armazena sessão para revive
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
                cout << "       Use um cliente novo para estabelecer conexão.\n";
                continue;
            }

            cout << "Tentando reviver sessão...\n";

            // Solicita mensagem para enviar junto com o revive
            cin.ignore();
            string reviveMessage = getInput("Digite uma mensagem para enviar com o revive: ");
            
            if (reviveMessage.empty()) {
                reviveMessage = "Revive test message";
                cout << "[INFO] Usando mensagem padrão: \"" << reviveMessage << "\"\n";
            }

            // Tenta fazer o revive da sessão
            if (p.zeroWay(reviveMessage)) {
                cout << "[OK] Sessão revivida com sucesso!\n";
                cout << "     Mensagem enviada junto com o revive.\n";
                connected = true;
            } else {
                cout << "[ERRO] Falha ao reviver a sessão.\n";
                cout << "       A sessão pode ter expirado no servidor.\n";
            }

        } else if (cmd == "4" || cmd == "status") {
            printStatus(p, connected);

        } else if (cmd == "5" || cmd == "help") {
            printHelp();

        } else if (cmd == "6" || cmd == "exit" || cmd == "quit" || cmd == "end") {
            // Se estiver conectado, salva e desconecta antes de sair
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