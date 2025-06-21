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
        // 1) Envia CONNECT
        Header h;
        h.seq = nextSeq++;
        h.wnd = window_size;
        h.sf |= FLAG_C;

        uint8_t buf[HDR_SIZE];
        serialize(h, buf);
        printHeader(h, "Pacote Enviado (CONNECT)");

        if (sendto(fd, buf, HDR_SIZE, 0, (sockaddr*)&srv, sizeof(srv)) < HDR_SIZE)
            return false;

        // 2) Recebe SETUP
        uint8_t rbuf[HDR_SIZE + DATA_MAX];
        sockaddr_in sa; socklen_t sl = sizeof(sa);
        if (recvfrom(fd, rbuf, sizeof(rbuf), 0, (sockaddr*)&sa, &sl) < HDR_SIZE)
            return false;

        Header r;
        deserialize(r, rbuf);
        printHeader(r, "Pacote Recebido (SETUP)");

        if (r.ack != 0 || !(r.sf & FLAG_AR))
            return false;

        // 3) Atualiza estado
        prevHdr        = r;
        hasPrev        = true;
        active         = true;
        lastCentralSeq = r.seq;
        window_size    = r.wnd;

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

        // Fragmentado
        if (msg.size() > DATA_MAX) {
            uint8_t fragment_id = nextSeq & 0xFF;
            size_t offset = 0;
            uint8_t fo = 0;

            while (offset < msg.size()) {
                size_t chunk = min(msg.size() - offset, (size_t)DATA_MAX);

                if (bytesInFlight + chunk > window_size) {
                    cerr << "[ERRO] Janela cheia ("
                         << bytesInFlight << "+" << chunk
                         << " > " << window_size
                         << "), aguarde ACK.\n";
                    return false;
                }

                Header h = prevHdr;
                h.seq = nextSeq++;
                h.ack = lastCentralSeq;
                h.wnd = window_size;

                uint32_t f = FLAG_ACK;
                if (offset + chunk < msg.size()) f |= FLAG_MB;
                h.sf  = (h.sf & ~0x1F) | f;
                h.fid = fragment_id;
                h.fo  = fo++;

                uint8_t buf[HDR_SIZE + DATA_MAX];
                serialize(h, buf);
                memcpy(buf + HDR_SIZE, msg.data() + offset, chunk);
                printHeader(h, "Pacote Enviado (DATA fragmentado)");

                bytesInFlight += chunk;
                if (sendto(fd, buf, HDR_SIZE + chunk, 0, (sockaddr*)&srv, sizeof(srv)) < 0)
                    return false;

                offset += chunk;
            }
            
            // Espera ACK final
            uint8_t rbuf[HDR_SIZE];
            sockaddr_in sa; socklen_t sl = sizeof(sa);
            if (recvfrom(fd, rbuf, HDR_SIZE, 0, (sockaddr*)&sa, &sl) < HDR_SIZE)
                return false;

            Header r; deserialize(r, rbuf);
            printHeader(r, "Pacote Recebido (DATA final)");
            if (!(r.sf & FLAG_ACK)) return false;

            bytesInFlight   = 0;
            window_size     = r.wnd;
            lastCentralSeq  = r.seq;
            prevHdr         = r;
            return true;
        }

        // sem fragmento
        size_t payloadSize = msg.size();

        if (bytesInFlight + payloadSize > window_size) {
            cerr << "[ERRO] Janela cheia ("
                 << bytesInFlight << "+" << payloadSize
                 << " > " << window_size
                 << "), aguarde ACK.\n";
            return false;
        }

        Header h = prevHdr;
        h.seq = nextSeq++;
        h.ack = lastCentralSeq;
        h.wnd = window_size;
        h.sf  = (h.sf & ~0x1F) | FLAG_ACK;

        uint8_t buf[HDR_SIZE + DATA_MAX];
        serialize(h, buf);
        memcpy(buf + HDR_SIZE, msg.data(), payloadSize);
        printHeader(h, "Pacote Enviado (DATA)");

        bytesInFlight += payloadSize;
        if (sendto(fd, buf, HDR_SIZE + payloadSize, 0, (sockaddr*)&srv, sizeof(srv)) < 0)
            return false;

        uint8_t rbuf[HDR_SIZE + DATA_MAX];
        sockaddr_in sa; socklen_t sl = sizeof(sa);
        if (recvfrom(fd, rbuf, sizeof(rbuf), 0, (sockaddr*)&sa, &sl) < HDR_SIZE)
            return false;

        Header r; deserialize(r, rbuf);
        printHeader(r, "Pacote Recebido (DATA)");
        if (!(r.sf & FLAG_ACK)) return false;

        // libera janela e atualiza estado
        bytesInFlight   = 0;
        window_size     = r.wnd;
        lastCentralSeq  = r.seq;
        prevHdr         = r;
        return true;
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

        // validação do bit A/R
        if (!(r.sf & FLAG_AR)) {
            cerr << "[ERRO] Revive rejeitado pelo servidor (A/R=0)\n";
            return false;
        }

        prevHdr        = r;
        active         = true;
        lastCentralSeq = r.seq;
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