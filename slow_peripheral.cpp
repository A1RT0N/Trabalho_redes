/*
Ayrton da Costa Ganem Filho - 14560190
Luiz Felipe Diniz Costa - 13782032
Cauê Paiva Lira - 14675416
*/

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
#include <cstdint> 
#include <vector> 

using namespace std;

// Tamanho fixo do cabeçalho e payload máximo
static const int   HDR_SIZE = 32;
static const int   DATA_MAX = 1440;

// Flags usadas no campo sf (5 bits menos significativos)
static const uint32_t FLAG_C   = 1 << 4;   ///< Conectar
static const uint32_t FLAG_R   = 1 << 3;   ///< Reviver / Desconectar
static const uint32_t FLAG_ACK = 1 << 2;   ///< Reconhecimento (Ack)
static const uint32_t FLAG_AR  = 1 << 1;   ///< Aceitar/Pronto
static const uint32_t FLAG_MB  = 1 << 0;   ///< Mais Bits (fragmentação)

// Observação: o data implementado já envia o ACK

/**
 * @struct SID
 * @brief Identificador de sessão (16 bytes).
 */
struct SID {
    uint8_t b[16];              ///< Bytes do ID

    /**
     * @brief Retorna um SID nulo (zeros).
     */
    static SID nil() {
        SID s{};
        memset(s.b, 0, 16);
        return s;
    }

    /**
     * @brief Compara igualdade de SIDs.
     * @param o Outro SID para comparação
     * @return true se bytes forem idênticos
     */
    bool isEqual(const SID& o) const {
        return memcmp(b, o.b, 16) == 0;
    }
};

/**
 * @struct Header
 * @brief Representa o cabeçalho do protocolo SLOW.
 */
struct Header {
    SID     sid;   ///< ID da Sessão (16 bytes)
    uint32_t sf;   ///< STTL (27 bits) | flags (5 bits)
    uint32_t seq;  ///< Número de sequência
    uint32_t ack;  ///< Número de reconhecimento (ACK)
    uint16_t wnd;  ///< Tamanho da janela
    uint8_t  fid;  ///< ID do fragmento
    uint8_t  fo;   ///< Offset do fragmento

    /**
     * @brief Construtor padrão zera todos os campos.
     */
    Header(): sid(SID::nil()), sf(0), seq(0), ack(0), wnd(0), fid(0), fo(0) {}
};

// Funções de (de)serialização little-endian para inteiros
void pack32(uint32_t v, uint8_t* p) {
    for (int i = 0; i < 4; i++) {
        p[i] = v & 0xFF;
        v >>= 8;
    }
}
uint32_t unpack32(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++)
        v |= (uint32_t)p[i] << (i*8);
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
    for (int i = 0; i < 2; i++)
        v |= (uint16_t)p[i] << (i*8);
    return v;
}



/**
 * @brief Serializa um Header em buffer de bytes.
 */
void serialize(const Header& h, uint8_t* buf) {
    memcpy(buf,       h.sid.b, 16);
    pack32(h.sf,     buf + 16);
    pack32(h.seq,    buf + 20);
    pack32(h.ack,    buf + 24);
    pack16(h.wnd,    buf + 28);
    buf[30] = h.fid;
    buf[31] = h.fo;
}

/**
 * @brief Desserializa bytes em um Header.
 */
void deserialize(Header& h, const uint8_t* buf) {
    memcpy(h.sid.b, buf, 16);
    h.sf  = unpack32(buf + 16);
    h.seq = unpack32(buf + 20);
    h.ack = unpack32(buf + 24);
    h.wnd = unpack16(buf + 28);
    h.fid = buf[30];
    h.fo  = buf[31];
}

/**
 * @brief Imprime todos os campos de um Header (hex e dec).
 * @param h Header a ser impresso
 * @param label Rótulo para identificação
 */
void printHeader(const Header& h, const string& label) {
    cout << "---- " << label << " ----\n";
    cout << "SID: ";
    for (int i = 0; i < 16; i++)
        cout << hex << setw(2) << setfill('0') << (int)h.sid.b[i];
    cout << dec << "\n";
    uint32_t flags =  h.sf & 0x1F;
    uint32_t sttl  = (h.sf >> 5) & 0x07FFFFFF;
    cout << "Flags: 0x" << hex << flags << dec << " ("<<flags<<")\n";
    cout << "STTL: "    << sttl  << "\n";
    cout << "SEQNUM: "  << h.seq  << "\n";
    cout << "ACKNUM: "  << h.ack  << "\n";
    cout << "WINDOW: "  << h.wnd  << "\n";
    cout << "FID: "     << (int)h.fid << "\n";
    cout << "FO: "      << (int)h.fo  << "\n\n";
}

/**
 * @struct PendingPacket
 * @brief Representa um pacote pendente na fila de retransmissão.
 */
struct PendingPacket {
    uint8_t  buffer[HDR_SIZE + DATA_MAX]; ///< Buffer completo do pacote
    size_t   length;                      ///< Tamanho total do pacote
    uint32_t seq;                         ///< Número de sequência
    size_t   dataSize;                    ///< Tamanho dos dados (sem cabeçalho)
    
    PendingPacket(const uint8_t* buf, size_t len, uint32_t sequence, size_t dSize) 
        : length(len), seq(sequence), dataSize(dSize) {
        memcpy(buffer, buf, len);
    }
};

/**
 * @class UDPPeripheral
 * @brief Gerencia socket UDP e implementa lógica do protocolo SLOW.
 */
class UDPPeripheral {
private:
    int        fd;              ///< File descriptor do socket
    sockaddr_in srv;            ///< Endereço do servidor
    Header     lastHdr;         ///< Último header armazenado
    Header     prevHdr;         ///< Header da última troca bem-sucedida
    bool       active    = false; ///< Conexão ativa?
    bool       hasPrev   = false; ///< Replay possível?
    uint32_t   nextSeq   = 0;     ///< Próximo sequence number
    uint32_t   lastCentralSeq = 0;///< Último seq do servidor
    uint32_t   window_size    = 5 * DATA_MAX; ///< Tamanho inicial da janela
    uint32_t   bytesInFlight  = 0; ///< Bytes enviados aguardando ACK
    vector<PendingPacket> pendingQueue; ///< Fila de pacotes pendentes
    static const int MAX_RETRIES = 3; ///< Máximo de tentativas de retransmissão

    uint16_t advertisedWindow() const {
        uint32_t livre = (window_size > bytesInFlight)
                        ? (window_size - bytesInFlight)
                        : 0;
        return static_cast<uint16_t>(std::min<uint32_t>(livre, UINT16_MAX));
    }

    /**
     * @brief Remove pacotes da fila com seq <= acknum e atualiza bytesInFlight.
     */
    void removePendingPackets(uint32_t acknum) {
        auto it = pendingQueue.begin();
        while (it != pendingQueue.end()) {
            if (it->seq <= acknum) {
                bytesInFlight -= it->dataSize;
                it = pendingQueue.erase(it);
            } else {
                ++it;
            }
        }
    }

    /**
     * @brief Envia um pacote com retransmissão até obter ACK.
     * @param buf Buffer do pacote completo
     * @param len Tamanho total do pacote  
     * @param seq Número de sequência
     * @param dataSize Tamanho dos dados (sem cabeçalho)
     * @return true se ACK recebido, false em caso de erro
     */
    bool sendWithRetry(const uint8_t* buf, size_t len, uint32_t seq, size_t dataSize) {
        pendingQueue.emplace_back(buf, len, seq, dataSize);
        bytesInFlight += dataSize;

        for (int attempt = 1; attempt <= MAX_RETRIES; ++attempt) {
            if (bytesInFlight > window_size) {
                bytesInFlight -= dataSize;
                pendingQueue.pop_back();
                return false;
            }

            if (sendto(fd, buf, len, 0, (sockaddr*)&srv, sizeof(srv)) < 0) {
                continue;
            }

            fd_set readfds;
            struct timeval timeout;
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);
            timeout.tv_sec = 2;
            timeout.tv_usec = 0;

            int result = select(fd + 1, &readfds, nullptr, nullptr, &timeout);
            
            if (result > 0 && FD_ISSET(fd, &readfds)) {
                uint8_t rbuf[HDR_SIZE];
                sockaddr_in sa;
                socklen_t sl = sizeof(sa);
                ssize_t recv_len = recvfrom(fd, rbuf, HDR_SIZE, 0, (sockaddr*)&sa, &sl);
                
                if (recv_len >= HDR_SIZE) {
                    Header r;
                    deserialize(r, rbuf);
                    
                    if (r.sf & FLAG_ACK) {
                        removePendingPackets(r.ack);
                        lastCentralSeq = r.seq;
                        prevHdr = r;
                        window_size = r.wnd;
                        return true;
                    }
                }
            }
        }

        bytesInFlight -= dataSize;
        pendingQueue.pop_back();
        return false;
    }

public:
    UDPPeripheral(): fd(-1) {}
    ~UDPPeripheral() { if (fd >= 0) close(fd); }

    /**
     * @brief Inicializa socket e configuração do servidor.
     * @param host IP ou hostname
     * @param port Porta UDP
     * @return true em sucesso, false caso contrário
     */
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

    /**
     * @brief Realiza handshake CONNECT→SETUP→ACK.
     */
    bool connect() {
        Header h;
        h.seq = nextSeq++;
        h.wnd = advertisedWindow();
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

        Header r; deserialize(r, rbuf);
        printHeader(r, "Pacote Recebido (SETUP)");
        if (r.ack != 0 || !(r.sf & FLAG_AR))
            return false;

        prevHdr        = r;
        hasPrev        = true;
        active         = true;
        lastCentralSeq = r.seq;
        nextSeq        = r.seq + 1;
        window_size    = r.wnd;
        bytesInFlight  = 0;
        pendingQueue.clear();
        
        return true;
    }

    /**
     * @brief Encerra sessão com CONNECT+REVIVE+ACK.
     */
    bool disconnect() {
        if (!active) return false;

        Header h = prevHdr;
        h.seq = nextSeq++;
        h.ack = lastCentralSeq;
        h.wnd = 0;
        h.sf  = (h.sf & ~0x1F) | FLAG_C | FLAG_R | FLAG_ACK;

        uint8_t buf[HDR_SIZE];
        serialize(h, buf);
        printHeader(h, "Pacote Enviado (DISCONNECT)");

        if (sendto(fd, buf, HDR_SIZE, 0, (sockaddr*)&srv, sizeof(srv)) < HDR_SIZE)
            return false;

        const int MAX_TRIES = 3;
        for (int i = 1; i <= MAX_TRIES; ++i) {
            uint8_t rbuf[HDR_SIZE];
            sockaddr_in sa; socklen_t sl = sizeof(sa);
            ssize_t rec = recvfrom(fd, rbuf, HDR_SIZE, 0, (sockaddr*)&sa, &sl);
            if (rec >= HDR_SIZE) {
                Header rr; deserialize(rr, rbuf);
                printHeader(rr, "Pacote Recebido (DISCONNECT)");
                if (rr.sf & FLAG_ACK) {
                    active = false;
                    bytesInFlight = 0;
                    pendingQueue.clear();
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @brief Envia mensagem (com fragmentação se > DATA_MAX).
     */
    bool sendData(const string& msg) {
        if (!active) return false;

        auto enviaFragmento = [&](const char* data, size_t len,
                                uint8_t fid, uint8_t fo, bool more) -> bool {
            Header h = prevHdr;
            h.seq = nextSeq++;
            h.ack = lastCentralSeq;
            h.wnd = advertisedWindow();
            h.sf  = (h.sf & ~0x1F) | FLAG_ACK | (more ? FLAG_MB : 0);
            h.fid = fid;
            h.fo  = fo;

            uint8_t buf[HDR_SIZE + DATA_MAX];
            serialize(h, buf);
            memcpy(buf + HDR_SIZE, data, len);

            return sendWithRetry(buf, HDR_SIZE + len, h.seq, len);
        };

        if (msg.size() > DATA_MAX || msg.size() > window_size) {
            uint8_t fid = nextSeq & 0xFF;
            uint8_t fo  = 0;
            size_t  off = 0;
            
            while (off < msg.size()) {
                size_t remaining = msg.size() - off;
                size_t maxChunk = std::min(remaining, (size_t)DATA_MAX);
                
                size_t available = (window_size > bytesInFlight) ? (window_size - bytesInFlight) : 0;
                
                while (available < maxChunk) {
                    if (!pendingQueue.empty()) {
                        fd_set readfds;
                        struct timeval timeout;
                        FD_ZERO(&readfds);
                        FD_SET(fd, &readfds);
                        timeout.tv_sec = 5;
                        timeout.tv_usec = 0;

                        int result = select(fd + 1, &readfds, nullptr, nullptr, &timeout);
                        
                        if (result > 0 && FD_ISSET(fd, &readfds)) {
                            uint8_t rbuf[HDR_SIZE];
                            sockaddr_in sa;
                            socklen_t sl = sizeof(sa);
                            ssize_t recv_len = recvfrom(fd, rbuf, HDR_SIZE, 0, (sockaddr*)&sa, &sl);
                            
                            if (recv_len >= HDR_SIZE) {
                                Header r;
                                deserialize(r, rbuf);
                                
                                if (r.sf & FLAG_ACK) {
                                    removePendingPackets(r.ack);
                                    lastCentralSeq = r.seq;
                                    prevHdr = r;
                                    window_size = r.wnd;
                                    available = (window_size > bytesInFlight) ? (window_size - bytesInFlight) : 0;
                                }
                            }
                        } else {
                            return false;
                        }
                    } else {
                        if (available == 0) {
                            return false;
                        }
                        maxChunk = available;
                        break;
                    }
                }
                
                size_t chunk = std::min(maxChunk, available);
                bool more = (off + chunk < msg.size());
                
                if (!enviaFragmento(msg.data() + off, chunk, fid, fo++, more)) {
                    return false;
                }
                    
                off += chunk;
            }
            
            return true;
        } else {
            return enviaFragmento(msg.data(), msg.size(), 0, 0, false);
        }
    }


    /**
     * @brief Armazena sessão atual para revive futuro.
     */
    void storeSession() {
        if (active) {
            lastHdr = prevHdr;
            hasPrev = true;
        }
    }

    /**
     * @brief Indica se há sessão para revive.
     */
    bool canRevive() const { return hasPrev; }

    /**
     * @brief Retoma sessão sem handshake completo (zero-way).
     */
    bool zeroWay(const string& msg) {
        if (!hasPrev) return false;

        Header h = lastHdr;
        h.seq = nextSeq++;
        h.ack = lastCentralSeq;
        h.wnd = window_size;
        h.sf  = (h.sf & ~0x1F) | FLAG_R | FLAG_ACK;

        uint8_t buf[HDR_SIZE + DATA_MAX];
        serialize(h, buf);
        memcpy(buf + HDR_SIZE, msg.data(), msg.size());
        printHeader(h, "Pacote Enviado (REVIVE)");

        if (sendto(fd, buf, HDR_SIZE + msg.size(), 0, (sockaddr*)&srv, sizeof(srv)) < 0)
            return false;

        uint8_t rbuf[HDR_SIZE + DATA_MAX];
        sockaddr_in sa; socklen_t sl = sizeof(sa);
        if (recvfrom(fd, rbuf, sizeof(rbuf), 0, (sockaddr*)&sa, &sl) < HDR_SIZE)
            return false;

        Header r;
        deserialize(r, rbuf);
        printHeader(r, "Pacote Recebido (REVIVE)");

        if (!(r.sf & FLAG_AR)) {
            return false;
        }

        prevHdr        = r;
        active         = true;
        lastCentralSeq = r.seq;
        nextSeq        = lastCentralSeq + 1;
        bytesInFlight  = 0;
        pendingQueue.clear();

        return true;
    }
};



// ---------------------- Interação com usuário ----------------------


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

/**
 * @brief Função principal: gerencia loop de comandos interativos.
 */
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