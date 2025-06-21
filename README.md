# Cliente UDPPeripheral (Protocolo SLOW)

**Autores**: Ayrton da Costa Ganem Filho (14560190), Luiz Felipe Diniz Costa (13782032), Cauê Paiva Lira (14675416)

## Visão Geral

Este programa implementa o protocolo de transporte SLOW sobre UDP (inspirado no QUIC), atuando como *peripheral*. Ele oferece as seguintes funcionalidades:

* **3-way connect**: handshake de conexão (CONNECT → SETUP → ACK)
* **Transferência de dados**: fragmentação de mensagens longas, controle de fluxo por janela deslizante e confirmação (ACK)
* **Disconnect**: encerramento formal da sessão (CONNECT+REVOKE+ACK)
* **0-way revive**: retomada de sessão inativa sem novo handshake completo

## Pré-requisitos

* Compilador C++17 (por exemplo, `g++`)
* Sistema POSIX (Linux, macOS)
* Make

## Compilação

No diretório do projeto, execute:

```bash
make
```

Isso irá gerar o executável `slow_peripheral`.

## Uso

```bash
make run
```

Após conectar, um menu interativo é exibido com as opções abaixo.

## Comandos Interativos

* `data` ou `1`      : enviar mensagem de texto para o servidor
* `disconnect` ou `2`: desconectar do servidor e armazenar sessão
* `revive` ou `3`    : reviver a sessão anteriormente armazenada
* `status` ou `4`    : exibir status da conexão e disponibilidade de *revive*
* `help` ou `5`      : mostrar este guia de comandos
* `exit` ou `6`      : desconectar (se conectado) e encerrar o programa

## Exemplos de Uso

```bash
$ ./slow_peripheral slow.gmelodie.com 7033
Conectando ao servidor slow.gmelodie.com:7033...
[OK] Conectado com sucesso!

> data
Digite sua mensagem: Olá, SLOW!
[OK] Mensagem enviada com sucesso!

> disconnect
Desconectando do servidor...
[OK] Desconectado com sucesso!

> revive
Digite uma mensagem para revive: Reativando sessão
[OK] Sessão revivida com sucesso!

> status
┌─────────────────────────────────────────────┐
│                  STATUS                    │
├─────────────────────────────────────────────┤
│ Servidor: slow.gmelodie.com:7033           │
│ Conexão:  [CONECTADO]                      │
│ Sessão:   [DISPONÍVEL]                     │
└─────────────────────────────────────────────┘

> exit
Até logo!
```

## Documentação do Código

Principais componentes:

* **Header**: estrutura que representa o cabeçalho SLOW, com métodos de (de)serialização *little-endian*.
* **UDPPeripheral**: classe responsável por gerenciar o socket UDP, implementar o handshake, fragmentação de dados, controle de fluxo e lógica de *revive* e *disconnect*.
* **Funções utilitárias**: para converter valores (`pack16`, `unpack32`, etc.) e imprimir o estado do cabeçalho.
