# Cliente **UDP Peripheral** – Protocolo **SLOW** (versão 2)

**Autores**
Ayrton da Costa Ganem Filho (14560190) · Luiz Felipe Diniz Costa (13782032) · Cauê Paiva Lira (14675416)

---

## Visão geral

Esta nova versão do *peripheral* SLOW expande a implementação original com:

| Recurso                                | O que mudou?                                                                                                                                                                      |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Controle de fluxo preciso**          | A janela anunciada ao servidor agora reflete o *buffer* local disponível em tempo real (`advertisedWindow()`), evitando *overrun*.                                                |
| **Gerenciamento de bytes em trânsito** | `bytesInFlight` rastreia dados não-confirmados, bloqueando novos envios quando ultrapassariam a janela remota.                                                                    |
| **Fragmentação inteligente**           | Mensagens maiores que `DATA_MAX` (1 440 bytes) são quebradas em blocos respeitando tanto `DATA_MAX` quanto o espaço restante da janela do servidor (`remoteWnd - bytesInFlight`). |
| **ACK automático**                     | Toda troca DATA↔ACK é tratada por `esperaAck()`, que atualiza `lastCentralSeq`, renova a janela e zera `bytesInFlight`.                                                           |
| **REVIVE zero-way robusto**            | Valida o bit **A/R** de aceitação; se rejeitado, informa o motivo.                                                                                                                |
| **Logs detalhados**                    | Função `printHeader()` exibe cada campo do cabeçalho; mensagens **DEBUG** mostram a “janela efetiva” antes de cada envio.                                                         |
| **Menu interativo revisado**           | Mesmo conjunto de comandos, mas com avisos/erros mais claros e mensagens de ajuda formatadas em box-drawing.                                                                      |

---

## Pré-requisitos

* Compilador **C++17**
  Recomendado: `g++` ≥ 9.0
* Sistema **POSIX** (Linux/macOS). Testado em Ubuntu 22.04
* **Make** (GNU Make)
* Permissão para criar sockets UDP na porta de origem aleatória

---

## Compilação

No diretório do projeto:

```bash
make
```

Gera o binário `slow_peripheral`.

---

## Execução rápida


```bash
make run           
```

---

## Menu de comandos

| Comando        | Alias            | Função                                                                        |
| -------------- | ---------------- | ----------------------------------------------------------------------------- |
| **data**       | `1`              | Envia texto ao servidor (fragmenta se necessário)                             |
| **disconnect** | `2`              | Termina a sessão via “CONNECT + REVIVE + ACK” e salva estado                  |
| **revive**     | `3`              | Restaura sessão salva (**zero-way handshake**) enviando uma mensagem opcional |
| **status**     | `4`              | Exibe host, estado da conexão e disponibilidade de *revive*                   |
| **help**       | `5`              | Mostra explicação dos comandos                                                |
| **exit**       | `6` `quit` `end` | Desconecta (se necessário) e finaliza o cliente                               |

---

## Exemplo de sessão

```text
=================================================
         UDP Peripheral Client v1.0
=================================================
Conectando ao servidor slow.gmelodie.com:7033...
[OK] Conectado com sucesso!

┌─────────────────────────────────────────────┐
│                  MENU                       │
│ 1. data       - Enviar dados                │
│ 2. disconnect - Desconectar do servidor     │
│ 3. revive     - Reviver sessão anterior     │
│ 4. status     - Ver status da conexão       │
│ 5. help       - Mostrar ajuda               │
│ 6. exit       - Sair do programa            │
└─────────────────────────────────────────────┘

> data
Digite sua mensagem: Mensagem gigante que será fragmentada...
[DEBUG] Janela efetiva do central: 1024 (reportada: 1024, bytes em trânsito: 0)
---- Pacote Enviado (DATA) ----
(... cabeçalho + payload ...)
---- Pacote Recebido (ACK DATA) ----
[DEBUG] Janela atualizada: 1024
[OK] Mensagem enviada com sucesso!

> disconnect
Desconectando do servidor...
---- Pacote Enviado (DISCONNECT) ----
---- Pacote Recebido (DISCONNECT) ----
[OK] Desconectado com sucesso!

> revive
Tentando reviver sessão...
Digite uma mensagem para enviar com o revive: Olá de novo!
---- Pacote Enviado (REVIVE) ----
---- Pacote Recebido (REVIVE) ----
[OK] Sessão revivida com sucesso!

> exit
Até logo!
```

---

## Estrutura do código-fonte

* **`SID`**
  *16 bytes* que identificam a sessão. Métodos utilitários `nil()` e `isEqual()`.

* **`Header`**
  Representa o cabeçalho SLOW (32 bytes). Construtor zera campos; macros `FLAG_*` definem bits de controle.

* **Funções de serialização** (`pack16/32`, `unpack16/32`, `serialize`, `deserialize`)
  Lidam com *little-endian* sem depender de `htonl/ntohl`.

* **`UDPPeripheral`**

  * `init()` – cria socket e resolve DNS
  * `connect()` – 3-way handshake (CONNECT → SETUP → ACK)
  * `sendData()` – fragmenta, envia e espera ACKs, respeitando `remoteWnd`
  * `disconnect()` – encerramento formal com confirmação
  * `zeroWay()` – revive sem handshake
  * Variáveis internas monitoram janela local, remota e bytes “em voo”

* **Interface CLI** (`main`)
  Menus ASCII, leitura segura de comandos, mensagens de erro/aviso padronizadas.

