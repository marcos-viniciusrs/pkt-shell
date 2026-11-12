# Conversor Packet Tracer em shell com bibliotecas nativas

`pkt-shell.sh` converte arquivos modernos `.pkt`/`.pka` para XML e faz a
operacao inversa. XML e texto; pode ser salvo com extensao `.txt` sem alterar
o conteudo. Nao e um resumo da rede: conserva o documento extraido inteiro.

## Uso

```sh
git clone https://github.com/marcos-viniciusrs/pkt-shell.git
```

Os nomes abaixo sao exemplos; informe o caminho do seu arquivo.

```sh
cd pkt-shell
./pkt-shell.sh decode minha-rede.pkt minha-rede-nativo.xml
./pkt-shell.sh decode minha-rede.pkt minha-rede-nativo.txt
./pkt-shell.sh encode minha-rede-nativo.xml minha-rede-recriado.pkt
```

Nao sobrescreve arquivos existentes. Para substituir deliberadamente:

```sh
./pkt-shell.sh --force decode minha-rede.pkt minha-rede-nativo.xml
```

Pode ser executado com `sh pkt-shell.sh ...`. Nao requer Bash, Python, pip,
Packet Tracer, acesso a internet ou downloads durante a execucao.

## Dependencias

O ponto de entrada e um script POSIX shell. O processamento binario usa um
auxiliar **C embutido no proprio script**, compilado em um diretorio temporario
em cada execucao. Portanto, esta solucao nao e implementada inteiramente em
shell: usa o compilador `cc`, a `libgcrypt` para Twofish-EAX e a `zlib` para
compressao, alem de utilitarios GNU coreutils (`mktemp`, `ln`, `mv`, etc.).
Os arquivos temporarios sao removidos ao sair.

Dependencias de compilacao, caso ainda nao estejam instaladas:

```sh
# Debian/Ubuntu
sudo apt install build-essential libgcrypt20-dev zlib1g-dev

# Fedora
sudo dnf install gcc libgcrypt-devel zlib-devel

# Arch Linux
sudo pacman -S --needed gcc libgcrypt zlib
```

Requer libgcrypt >= 1.7.0 e zlib >= 1.2.9 (funcao `uncompress2`).
Esses componentes de desenvolvimento ja estavam presentes na maquina utilizada.
Nao basta chamar `openssl enc`: o OpenSSL instalado nao disponibiliza Twofish.
O comando `gpg` trabalha com o formato OpenPGP, diferente do container PKT.

## Formato e implementacao

Referencia inspecionada:
[izerhaf7/python-pka-to-xml](https://github.com/izerhaf7/python-pka-to-xml),
commit `23f1387f8bf5725c98215be7d7bb611c681a9484`, em especial
`pka2xml/__init__.py`, `__main__.py` e `_twofish.py`.

Decodificacao:

1. Para cada posicao `i`, inverter a ordem dos bytes e aplicar XOR com
   `(n - i*n) & 255`, onde `n` e o tamanho total.
2. Decifrar com Twofish-EAX: chave de 16 bytes `0x89`, IV de 16 bytes `0x10`.
   Os ultimos 16 bytes sao a etiqueta de autenticacao, conferida antes de
   descompactar ou gravar a saida.
3. Aplicar XOR com `(m-i) & 255`, onde `m` e o tamanho do resultado decifrado.
4. Ler o tamanho descompactado nos primeiros quatro bytes, em big-endian,
   e descompactar o restante com zlib. Conferir o tamanho e o consumo do fluxo.

A codificacao inverte essas etapas. A libgcrypt substitui toda a implementacao
Python de Twofish, CMAC e CTR. Referencia da API:
[manual oficial de libgcrypt](https://gnupg.org/documentation/manuals/gcrypt/Working-with-cipher-handles.html).

O resultado e publicado somente depois do sucesso. Por padrao, arquivos de
destino existentes sao recusados, inclusive links simbolicos. O mesmo arquivo
nao pode ser usado como entrada e saida. Limite de 512 MiB tanto para a entrada
quanto para o XML descompactado; o processamento e feito em memoria.

Escopo: mesmo container moderno do repositorio de referencia. Formatos antigos
que usam apenas XOR nao sao suportados. `encode` empacota os bytes recebidos;
nao verifica a estrutura XML nem a validade da topologia para o Packet Tracer.
A abertura do PKT recriado no aplicativo precisa ser verificada separadamente.

## Licenca da referencia

A implementacao foi reescrita para as APIs nativas. O aviso MIT do repositorio
de referencia foi conservado em `LICENSE-pkt-reference.txt`.

## Validacao executada

- `shellcheck pkt-shell.sh`: aprovado; C compilado com `-Wall -Wextra -Werror`.
- Arquivo real de teste: XML de 3.056.919 bytes identico byte por byte ao
  extraido pela ferramenta Python (96 dispositivos).
- Projeto completo: codificacao nativa aceita pelo decodificador Python,
  recuperando exatamente o XML; conversao de ida e volta nativa tambem identica.
- Compatibilidade cruzada com Python nos dois sentidos para entradas de
  0, 1, 15, 16, 17, 255, 256, 257 e 4096 bytes.
- Arquivo adulterado: etiqueta EAX rejeitada; entrada truncada recusada;
  nenhuma saida parcial publicada, inclusive com `--force` e destino existente.
- Sobrescrita recusada por padrao; `--force` verificado; entrada igual a saida
  recusada; nomes com espacos e recusa de link simbolico de destino verificados.

Python foi utilizado apenas como referencia de teste, nao pelo script.
O Packet Tracer nao foi utilizado para validar a abertura do arquivo recriado.
