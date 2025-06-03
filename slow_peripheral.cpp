#include <iostream>
#include <vector>
#include <map>
#include <queue>
#include <string>
#include <cstring>
#include <random>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <algorithm>      // <- para std::min
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

// SLOW Protocol Constants
#define SLOW_PORT 7033
#define MAX_PACKET_SIZE 1472
#define MAX_DATA_SIZE 1440
#define UUID_SIZE 16

// — Correção dos valores das flags —
// Cada flag deve ficar em um bit de 0 a 4 antes de ser shiftada em 27 bits:
//  bit  0  = CONNECT
//  bit  1  = REVIVE
//  bit  2  = ACK
//  bit  3  = ACCEPT/REJECT
//  bit  4  = MORE_BITS
#define FLAG_CONNECT        0x01  // (1 << 0)  → bit 27 depois do shift
#define FLAG_REVIVE         0x02  // (1 << 1)  → bit 28 depois do shift
#define FLAG_ACK            0x04  // (1 << 2)  → bit 29 depois do shift
#define FLAG_ACCEPT_REJECT  0x08  // (1 << 3)  → bit 30 depois do shift
#define FLAG_MORE_BITS      0x10  // (1 << 4)  → bit 31 depois do shift

// UUID v8 constants
#define UUID_VERSION_8 0x8
#define UUID_VARIANT_RFC4122 0x2

// SLOW Packet Structure (for internal use)
struct SlowPacket {
    uint8_t sid[16];             // Session ID (UUIDv8) - 128 bits
    uint32_t sttl;               // Session TTL (ms) - 27 bits (armazenado em 32 para facilitar)
    uint8_t flags;               // SLOW Flags - 5 bits
    uint32_t seqnum;             // Sequence Number - 32 bits
    uint32_t acknum;             // Acknowledgement Number - 32 bits
    uint16_t window;             // Window Size - 16 bits
    uint8_t fid;                 // Fragment ID - 8 bits
    uint8_t fo;                  // Fragment Offset - 8 bits
    uint8_t data[MAX_DATA_SIZE]; // Data payload
    uint16_t data_len;           // Actual data length (não faz parte do wire format)
};

// Fragment Buffer Entry
struct FragmentBuffer {
    std::map<uint8_t, std::vector<uint8_t>> fragments; // fo → data
    bool complete;
    uint8_t expected_fragments;

    FragmentBuffer() : complete(false), expected_fragments(0) {}
};

class SlowPeripheral {
private:
    int sock_fd;
    struct sockaddr_in central_addr;
    uint8_t session_id[16];
    uint32_t next_seqnum;
    uint32_t last_acknum;
    uint16_t window_size;
    uint32_t session_ttl;
    bool connected;
    bool session_active;

    // Sliding window management
    std::queue<SlowPacket> send_queue;
    std::map<uint32_t, SlowPacket> unacked_packets;
    uint16_t remote_window;
    uint32_t last_acked_seqnum;

    // Fragmentation support
    std::map<uint8_t, FragmentBuffer> fragment_buffers; // fid → buffer
    uint8_t next_fid;

    // Threading support
    std::mutex state_mutex;
    std::condition_variable ack_cv;
    std::thread receiver_thread;
    bool running;

    // Buffer management
    std::vector<uint8_t> receive_buffer;
    static const size_t BUFFER_SIZE = 8192;

public:
    SlowPeripheral() : sock_fd(-1), next_seqnum(1), last_acknum(0),
                       window_size(BUFFER_SIZE), session_ttl(0),
                       connected(false), session_active(false),
                       remote_window(0), last_acked_seqnum(0),
                       next_fid(1), running(false) {
        memset(session_id, 0, sizeof(session_id));
        receive_buffer.resize(BUFFER_SIZE);
    }

    ~SlowPeripheral() {
        disconnect();
        cleanup();
    }

    // Resolve hostname to IP address
    std::string resolve_hostname(const std::string& hostname) {
        struct addrinfo hints, *result;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;      // IPv4
        hints.ai_socktype = SOCK_DGRAM; // UDP

        int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
        if (status != 0) {
            std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
            return "";
        }

        struct sockaddr_in* addr_in = (struct sockaddr_in*)result->ai_addr;
        std::string ip = inet_ntoa(addr_in->sin_addr);

        freeaddrinfo(result);
        return ip;
    }

    // Generate UUIDv8 according to RFC9562
    void generate_uuid_v8(uint8_t* uuid) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);

        // Fill with random data
        for (int i = 0; i < 16; i++) {
            uuid[i] = dis(gen);
        }

        // Set version (4 bits in byte 6, upper nibble)
        uuid[6] = (uuid[6] & 0x0F) | (UUID_VERSION_8 << 4);

        // Set variant (2 bits in byte 8, upper 2 bits)
        uuid[8] = (uuid[8] & 0x3F) | (UUID_VARIANT_RFC4122 << 6);
    }

    // Generate nil UUID
    void generate_nil_uuid(uint8_t* uuid) {
        memset(uuid, 0, 16);
    }

    // Initialize socket e central address
    bool init(const std::string& central_host) {
        // Resolve hostname se não for IP numérico
        std::string central_ip;
        if (central_host.find_first_not_of("0123456789.") == std::string::npos) {
            central_ip = central_host;
        } else {
            central_ip = resolve_hostname(central_host);
            if (central_ip.empty()) {
                std::cerr << "Failed to resolve hostname: " << central_host << std::endl;
                return false;
            }
            std::cout << "Resolved " << central_host << " to " << central_ip << std::endl;
        }

        sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_fd < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }

        memset(&central_addr, 0, sizeof(central_addr));
        central_addr.sin_family = AF_INET;
        central_addr.sin_port = htons(SLOW_PORT);

        if (inet_pton(AF_INET, central_ip.c_str(), &central_addr.sin_addr) <= 0) {
            std::cerr << "Invalid IP address: " << central_ip << std::endl;
            return false;
        }

        // Inicia thread de recepção
        running = true;
        receiver_thread = std::thread(&SlowPeripheral::receiver_loop, this);

        return true;
    }

    // Serialize packet to wire format (little endian)
    std::vector<uint8_t> serialize_packet(const SlowPacket& packet) {
        std::vector<uint8_t> buffer(32 + packet.data_len); // Cabeçalho = 32 bytes
        size_t offset = 0;

        // Session ID (16 bytes)
        memcpy(buffer.data() + offset, packet.sid, 16);
        offset += 16;

        // STTL (27 bits) + Flags (5 bits) = 32 bits total (little endian)
        uint32_t sttl_masked = packet.sttl & 0x07FFFFFF;      // mantém apenas 27 bits
        uint32_t flags_shifted = (uint32_t)(packet.flags & 0x1F) << 27; // mantém 5 bits e shift
        uint32_t sttl_flags = sttl_masked | flags_shifted;

        // Armazena em little endian
        buffer[offset] = (sttl_flags) & 0xFF;
        buffer[offset + 1] = (sttl_flags >> 8) & 0xFF;
        buffer[offset + 2] = (sttl_flags >> 16) & 0xFF;
        buffer[offset + 3] = (sttl_flags >> 24) & 0xFF;
        offset += 4;

        // Sequence number (little endian)
        buffer[offset] = packet.seqnum & 0xFF;
        buffer[offset + 1] = (packet.seqnum >> 8) & 0xFF;
        buffer[offset + 2] = (packet.seqnum >> 16) & 0xFF;
        buffer[offset + 3] = (packet.seqnum >> 24) & 0xFF;
        offset += 4;

        // Acknowledgement number (little endian)
        buffer[offset] = packet.acknum & 0xFF;
        buffer[offset + 1] = (packet.acknum >> 8) & 0xFF;
        buffer[offset + 2] = (packet.acknum >> 16) & 0xFF;
        buffer[offset + 3] = (packet.acknum >> 24) & 0xFF;
        offset += 4;

        // Window size (little endian)
        buffer[offset] = packet.window & 0xFF;
        buffer[offset + 1] = (packet.window >> 8) & 0xFF;
        offset += 2;

        // Fragment ID
        buffer[offset] = packet.fid;
        offset += 1;

        // Fragment Offset
        buffer[offset] = packet.fo;
        offset += 1;

        // Dados
        if (packet.data_len > 0) {
            memcpy(buffer.data() + offset, packet.data, packet.data_len);
        }

        return buffer;
    }

    // Deserialize packet from wire format (little endian)
    SlowPacket deserialize_packet(const std::vector<uint8_t>& buffer) {
        SlowPacket packet;
        memset(&packet, 0, sizeof(packet));

        if (buffer.size() < 32) {
            return packet; // Pacote inválido
        }

        size_t offset = 0;

        // Session ID
        memcpy(packet.sid, buffer.data() + offset, 16);
        offset += 16;

        // STTL + Flags (little endian)
        uint32_t sttl_flags = 0;
        sttl_flags |= buffer[offset];
        sttl_flags |= (uint32_t)buffer[offset + 1] << 8;
        sttl_flags |= (uint32_t)buffer[offset + 2] << 16;
        sttl_flags |= (uint32_t)buffer[offset + 3] << 24;

        packet.sttl = sttl_flags & 0x07FFFFFF;
        packet.flags = (sttl_flags >> 27) & 0x1F;
        offset += 4;

        // Sequence number (little endian)
        packet.seqnum = 0;
        packet.seqnum |= buffer[offset];
        packet.seqnum |= (uint32_t)buffer[offset + 1] << 8;
        packet.seqnum |= (uint32_t)buffer[offset + 2] << 16;
        packet.seqnum |= (uint32_t)buffer[offset + 3] << 24;
        offset += 4;

        // Acknowledgment number (little endian)
        packet.acknum = 0;
        packet.acknum |= buffer[offset];
        packet.acknum |= (uint32_t)buffer[offset + 1] << 8;
        packet.acknum |= (uint32_t)buffer[offset + 2] << 16;
        packet.acknum |= (uint32_t)buffer[offset + 3] << 24;
        offset += 4;

        // Window size (little endian)
        packet.window = buffer[offset] | ((uint16_t)buffer[offset + 1] << 8);
        offset += 2;

        // Fragment ID
        packet.fid = buffer[offset];
        offset += 1;

        // Fragment Offset
        packet.fo = buffer[offset];
        offset += 1;

        // Dados
        packet.data_len = buffer.size() - offset;
        if (packet.data_len > 0 && packet.data_len <= MAX_DATA_SIZE) {
            memcpy(packet.data, buffer.data() + offset, packet.data_len);
        } else {
            packet.data_len = 0;
        }

        return packet;
    }

    // Send packet with retry logic
    bool send_packet(const SlowPacket& packet, bool wait_for_ack = true) {
        std::vector<uint8_t> serialized = serialize_packet(packet);

        std::unique_lock<std::mutex> lock(state_mutex);

        // Sliding-window: aguarda espaço se necessário
        if (wait_for_ack && packet.data_len > 0) {
            size_t bytes_in_flight = 0;
            for (const auto& pair : unacked_packets) {
                bytes_in_flight += pair.second.data_len;
            }

            if (bytes_in_flight + packet.data_len > remote_window) {
                std::cout << "Waiting for window space... (in_flight=" << bytes_in_flight
                          << ", remote_window=" << remote_window << ")" << std::endl;
                ack_cv.wait(lock, [this, &packet]() {
                    size_t current_in_flight = 0;
                    for (const auto& pair : unacked_packets) {
                        current_in_flight += pair.second.data_len;
                    }
                    return current_in_flight + packet.data_len <= remote_window;
                });
            }
        }

        lock.unlock();

        // Envia via UDP
        ssize_t sent = sendto(sock_fd, serialized.data(), serialized.size(), 0,
                             (struct sockaddr*)&central_addr, sizeof(central_addr));

        if (sent < 0) {
            perror("sendto");
            return false;
        }

        lock.lock();

        // Armazena para retransmissão se for pacote de dados
        if (wait_for_ack && packet.data_len > 0) {
            unacked_packets[packet.seqnum] = packet;
        }

        std::cout << "Sent packet: seqnum=" << packet.seqnum
                  << ", flags=0x" << std::hex << (int)packet.flags << std::dec
                  << ", data_len=" << packet.data_len << std::endl;

        return true;
    }

    // 3-way connect implementation
    bool connect_3way() {
        SlowPacket connect_packet = {};

        // Passo 1: Send Connect
        generate_nil_uuid(connect_packet.sid);
        connect_packet.sttl    = 0;
        connect_packet.flags   = FLAG_CONNECT;
        connect_packet.seqnum  = 0;
        connect_packet.acknum  = 0;
        connect_packet.window  = window_size;
        connect_packet.fid     = 0;
        connect_packet.fo      = 0;
        connect_packet.data_len = 0;

        if (!send_packet(connect_packet, false)) {
            return false;
        }

        // Aguarda resposta de Setup (aceitação)
        std::unique_lock<std::mutex> lock(state_mutex);
        auto timeout = std::chrono::steady_clock::now() + std::chrono::seconds(10);

        if (!ack_cv.wait_until(lock, timeout, [this]() { return connected; })) {
            std::cerr << "Connection timeout" << std::endl;
            return false;
        }

        std::cout << "3-way handshake completed successfully. Remote window = " << remote_window << std::endl;
        return true;
    }

    // 0-way connect (revive) implementation
    bool connect_0way(const std::vector<uint8_t>& data) {
        if (!session_active) {
            std::cerr << "No previous session to revive" << std::endl;
            return false;
        }
        return send_data_internal(data, true);
    }

    // Reassemble fragmented data
    std::vector<uint8_t> reassemble_fragments(uint8_t fid) {
        std::vector<uint8_t> result;
        if (fragment_buffers.find(fid) == fragment_buffers.end()) {
            return result;
        }
        FragmentBuffer& buffer = fragment_buffers[fid];
        if (!buffer.complete) {
            return result;
        }
        for (uint8_t fo = 0; fo < buffer.expected_fragments; fo++) {
            if (buffer.fragments.find(fo) != buffer.fragments.end()) {
                const auto& fragment_data = buffer.fragments[fo];
                result.insert(result.end(), fragment_data.begin(), fragment_data.end());
            }
        }
        fragment_buffers.erase(fid);
        return result;
    }

    // Internal data sending with dynamic fragmentation + sliding‐window
    bool send_data_internal(const std::vector<uint8_t>& data, bool revive = false) {
        // Se ainda não conectado ou sem sessão ativa, recusa
        if (!connected && !session_active) {
            std::cerr << "Not connected" << std::endl;
            return false;
        }

        size_t offset = 0;
        uint8_t fid = next_fid++;   // identificador único de fragmentação para toda esta mensagem
        uint8_t fo  = 0;            // offset de fragmento, incrementa a cada chunk enviado

        while (offset < data.size()) {
            // 1) Espera até que haja pelo menos 1 byte de espaço livre na janela
            std::unique_lock<std::mutex> lock(state_mutex);
            ack_cv.wait(lock, [this]() {
                size_t in_flight = 0;
                for (const auto& pair : unacked_packets) {
                    in_flight += pair.second.data_len;
                }
                // Se houver espaço para enviar pelo menos 1 byte, retorna true
                return in_flight < remote_window;
            });

            // 2) Recalcula bytes em tráfego e o espaço livre
            size_t in_flight = 0;
            for (const auto& pair : unacked_packets) {
                in_flight += pair.second.data_len;
            }
            size_t space = (remote_window > in_flight) ? (remote_window - in_flight) : 0;

            lock.unlock();

            if (space == 0) {
                // Sem espaço, volta a esperar no wait()
                continue;
            }

            // 3) Define o tamanho do próximo chunk:
            //    não pode ultrapassar MAX_DATA_SIZE,
            //    nem ultrapassar os bytes restantes (data.size() - offset),
            //    nem ultrapassar 'space' (espaço livre na janela).
            size_t bytes_restantes = data.size() - offset;
            size_t chunk_size = std::min((size_t)MAX_DATA_SIZE, std::min(bytes_restantes, space));

            // 4) Prepara o pacote SLOW
            SlowPacket packet;
            memset(&packet, 0, sizeof(packet));

            memcpy(packet.sid, session_id, 16);
            packet.sttl   = session_ttl;
            packet.flags  = FLAG_ACK;
            if (revive && (offset == 0)) {
                // só o primeiro fragmento leva FLAG_REVIVE
                packet.flags |= FLAG_REVIVE;
            }
            // se não for o último fragmento, sinaliza MORE_BITS
            if (offset + chunk_size < data.size()) {
                packet.flags |= FLAG_MORE_BITS;
            }

            packet.seqnum = next_seqnum++;
            packet.acknum = last_acknum;
            packet.window = window_size - receive_buffer.size();
            packet.fid    = fid;
            packet.fo     = fo++;

            // Copia exatamente 'chunk_size' bytes para packet.data
            memcpy(packet.data, data.data() + offset, chunk_size);
            packet.data_len = static_cast<uint16_t>(chunk_size);

            // 5) Envia via send_packet (que já controla reenvio e sliding window)
            if (!send_packet(packet)) {
                return false;
            }

            revive = false;   // somente o primeiro fragmento
            offset += chunk_size;
        }

        return true;
    }

    // Send data (public interface)
    bool send_data(const std::vector<uint8_t>& data) {
        if (!connected && !session_active) {
            std::cerr << "Not connected" << std::endl;
            return false;
        }
        return send_data_internal(data);
    }

    // Send data from string
    bool send_data(const std::string& data) {
        std::vector<uint8_t> vec_data(data.begin(), data.end());
        return send_data(vec_data);
    }

    // Disconnect implementation
    bool disconnect() {
        if (!connected && !session_active) {
            return true;
        }

        SlowPacket disconnect_packet = {};
        memcpy(disconnect_packet.sid, session_id, 16);
        disconnect_packet.sttl    = session_ttl;
        // Combinamos flags ACK + CONNECT + REVIVE para sinalizar disconnect
        disconnect_packet.flags   = FLAG_ACK | FLAG_CONNECT | FLAG_REVIVE;
        disconnect_packet.seqnum  = next_seqnum++;
        disconnect_packet.acknum  = last_acknum;
        disconnect_packet.window  = 0;
        disconnect_packet.fid     = 0;
        disconnect_packet.fo      = 0;
        disconnect_packet.data_len = 0;

        bool result = send_packet(disconnect_packet, false);

        connected = false;
        session_active = true; // Mantém sessão para potencial 0-way reconnect

        std::cout << "Disconnected (session preserved for 0-way reconnect)" << std::endl;
        return result;
    }

    // Process received packets
    void process_packet(const SlowPacket& packet) {
        std::lock_guard<std::mutex> lock(state_mutex);

        std::cout << "Received packet: seqnum=" << packet.seqnum
                  << ", acknum=" << packet.acknum
                  << ", flags=0x" << std::hex << (int)packet.flags << std::dec
                  << ", window=" << packet.window << std::endl;

        // ------------------------------------------------------------
        // Etapa 2 do 3-way connect: qualquer pacote com seqnum != 0
        // e ainda não conectado é tratado como “Setup/Accept”
        // ------------------------------------------------------------
        if (!connected && packet.seqnum != 0) {
            // Trata como aceitação, sem checar FLAG_ACCEPT_REJECT
            memcpy(session_id, packet.sid, 16);
            session_ttl        = packet.sttl;
            next_seqnum        = packet.seqnum + 1;
            // Atualiza a janela remota; assegura que nunca será zero
            remote_window      = packet.window;
            if (remote_window == 0) {
                remote_window = window_size;
                std::cerr << "Received zero window from central; usando window_size padrão: "
                          << remote_window << std::endl;
            } else {
                std::cout << "Remote window set to " << remote_window << std::endl;
            }
            connected          = true;
            session_active     = true;
            last_acknum        = packet.seqnum;
            std::cout << "Connection accepted (Setup recebido)" << std::endl;
            ack_cv.notify_all();
            return;
        }

        // ------------------------------------------------------------
        // Após estar connected, pacotes com FLAG_ACK tratam sliding window
        // ------------------------------------------------------------
        if (connected && (packet.flags & FLAG_ACK)) {
            // Atualiza sliding window
            if (packet.acknum >= last_acked_seqnum) {
                auto it = unacked_packets.begin();
                while (it != unacked_packets.end()) {
                    if (it->first <= packet.acknum) {
                        it = unacked_packets.erase(it);
                    } else {
                        ++it;
                    }
                }
                last_acked_seqnum = packet.acknum;
                remote_window     = packet.window;  // Atualiza janela remota dinamicamente
                std::cout << "ACK recebido para seqnum " << packet.acknum
                          << ", nova janela=" << packet.window << std::endl;
            }
            last_acknum = packet.seqnum;
            ack_cv.notify_all();
        }

        // ------------------------------------------------------------
        // Tratamento de dados fragmentados ou não
        // ------------------------------------------------------------
        if (packet.data_len > 0) {
            if (packet.flags & FLAG_MORE_BITS) {
                // Armazena fragmento intermediário
                FragmentBuffer& buffer = fragment_buffers[packet.fid];
                buffer.fragments[packet.fo] = std::vector<uint8_t>(
                    packet.data, packet.data + packet.data_len);
            } else {
                // Último fragmento (ou pacote único)
                if (fragment_buffers.find(packet.fid) != fragment_buffers.end()) {
                    FragmentBuffer& buffer = fragment_buffers[packet.fid];
                    buffer.fragments[packet.fo] =
                        std::vector<uint8_t>(packet.data, packet.data + packet.data_len);
                    buffer.expected_fragments = packet.fo + 1;
                    buffer.complete = true;

                    // Reúne todos os fragmentos
                    auto complete_data = reassemble_fragments(packet.fid);
                    if (!complete_data.empty()) {
                        std::cout << "Reassembled " << complete_data.size()
                                  << " bytes de " << (int)buffer.expected_fragments
                                  << " fragments" << std::endl;
                    }
                } else {
                    // Mensagem única (não fragmentada)
                    std::cout << "Received single fragment data: "
                              << packet.data_len << " bytes" << std::endl;
                }
            }
        }
    }

    // Retorna true se ainda houver pacotes não reconhecidos (in_flight)
    bool has_unacked_data() {
        std::lock_guard<std::mutex> lock(state_mutex);
        return !unacked_packets.empty();
    }

    // Receiver thread loop
    void receiver_loop() {
        uint8_t buffer[MAX_PACKET_SIZE];
        struct sockaddr_in sender_addr;
        socklen_t sender_len = sizeof(sender_addr);

        while (running) {
            ssize_t received = recvfrom(sock_fd, buffer, sizeof(buffer), 0,
                                       (struct sockaddr*)&sender_addr, &sender_len);

            if (received > 0) {
                std::vector<uint8_t> packet_data(buffer, buffer + received);
                SlowPacket packet = deserialize_packet(packet_data);
                process_packet(packet);
            } else if (received < 0) {
                if (running) {
                    perror("recvfrom");
                }
                break;
            }
        }
    }

    // Cleanup resources
    void cleanup() {
        running = false;
        if (receiver_thread.joinable()) {
            receiver_thread.join();
        }
        if (sock_fd >= 0) {
            close(sock_fd);
            sock_fd = -1;
        }
    }

    // Get connection status
    bool is_connected() const {
        return connected;
    }

    bool has_active_session() const {
        return session_active;
    }
};

// Example usage and testing
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <central_host>" << std::endl;
        std::cout << "Example: " << argv[0] << " slow.gmelodie.com" << std::endl;
        std::cout << "Example: " << argv[0] << " 127.0.0.1" << std::endl;
        return 1;
    }

    SlowPeripheral peripheral;

    if (!peripheral.init(argv[1])) {
        std::cerr << "Failed to initialize peripheral" << std::endl;
        return 1;
    }

    // Test 3-way connect
    std::cout << "Testing 3-way connect..." << std::endl;
    if (peripheral.connect_3way()) {
        std::cout << "3-way connect successful!" << std::endl;

        // —──────────—
        // 1) Envia primeiro pacote pequeno (45 bytes)
        // —──────────—
        std::cout << "Sending test data..." << std::endl;
        std::string test_data = "Hello, SLOW Protocol! This is a test message.";
        if (peripheral.send_data(test_data)) {
            std::cout << "Data sent, aguardando ACK desse pacote pequeno..." << std::endl;

            // Aguarda até que não haja mais pacotes não reconhecidos
            while (peripheral.has_unacked_data()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            std::cout << "ACK do pacote pequeno recebido. Agora fragmentamos o dado grande." << std::endl;
        } else {
            std::cerr << "Falha ao enviar o pacote pequeno." << std::endl;
        }

        // —──────────—
        // 2) Agora enviamos o dado grande (2000 'A's + "END_OF_LARGE_DATA")
        // —──────────—
        std::cout << "Testing fragmentation with large data..." << std::endl;
        std::string large_data(2000, 'A'); // 2000 bytes de 'A'
        large_data += "END_OF_LARGE_DATA";
        if (peripheral.send_data(large_data)) {
            std::cout << "Large data sent successfully!" << std::endl;
        } else {
            std::cerr << "Falha ao enviar pacote fragmentado grande." << std::endl;
        }

        // Wait a bit
        std::this_thread::sleep_for(std::chrono::seconds(2));

        // Test disconnect
        std::cout << "Testing disconnect..." << std::endl;
        if (peripheral.disconnect()) {
            std::cout << "Disconnect successful!" << std::endl;

            // Test 0-way reconnect
            std::cout << "Testing 0-way reconnect..." << std::endl;
            std::string reconnect_data = "Reconnecting with 0-way connect!";
            if (peripheral.connect_0way(std::vector<uint8_t>(reconnect_data.begin(), reconnect_data.end()))) {
                std::cout << "0-way reconnect successful!" << std::endl;
            }
        }
    } else {
        std::cerr << "3-way connect failed!" << std::endl;
    }

    // Manter thread viva por um tempo para receber respostas
    std::this_thread::sleep_for(std::chrono::seconds(5));

    return 0;
}
