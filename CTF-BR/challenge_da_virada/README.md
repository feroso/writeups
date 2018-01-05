# CHALLENGE DA VIRADA

> CHALLENGE DA VIRADA, para os verdadeiros players hardcore, que comemoram no PC! Valendo Internet Fame (Entrada no Hall of Fame do CTF-BR) e talvez um prêmio bônus!
>
> O primeiro que mandar a flag para contato at ctf-br.org será o vencedor.
>
> Nome: Baby RISC-V
>
> Categoria: Reversing
>
> Link: http://ctf-br.org/files/challenge_da_virada/babyriscv.tar.gz

Para começar bem os estudos do ano, o CTF-BR lançou um desafio de engenharia reversa bem interessante, pois foi necessário estudar uma nova arquitetura de processadores para poder concluir o desafio.

Iniciando a análise do binário:
```shell
$ file babyriscv 
babyriscv: ELF 64-bit LSB executable, UCB RISC-V, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-riscv64-lp64d.so.1, for GNU/Linux 3.0.0, not stripped
```

Pelo nome do desafio e pelo output do comando file, sabemos que é um binário compilado para arquitetura RISC-V.
Como é uma arquitetura que até então eu desconhecia, foi necessário diversas pesquisas no google para entender mais sobre a arquitetura e o processo de reversa desse binário.

> RISC-V (pronounced "risk-five") is an open instruction set architecture (ISA) based on established reduced instruction set computing (RISC) principles.

Link para a especificação das intruções do RISC-V, muito útil para entender os mnemônicos no processo de engenharia reversa:
https://content.riscv.org/wp-content/uploads/2017/05/riscv-spec-v2.2.pdf

Durante as pesquisas, encontrei um disassembler de RISC-V para o IDA (https://github.com/0xDeva/ida-cpu-RISC-V), porém não funcionou corretamente. 
Portanto segui a análise com o Radare2, que possuí disassembler para RISC-V.

Carregando o binário no Radare2 e verificando suas infos:
```shell
$ r2 babyriscv 
Unknown DW_FORM 0x06
 -- Use +,-,*,/ to change the size of the block
[0x000103bc]> i
blksz    0x0
block    0x100
fd       3
file     babyriscv
format   elf64
iorw     false
mode     -r-x
size     0x2d08
humansz  11.3K
type     EXEC (Executable file)
arch     riscv
binsz    9414
bintype  elf
bits     64
canary   false
class    ELF64
crypto   false
endian   little
havecode true
intrp    /lib/ld-linux-riscv64-lp64d.so.1
lang     c
linenum  true
lsyms    true
machine  RISC V
nx       false
os       linux
pic      false
relocs   true
relro    partial
rpath    NONE
static   false
stripped false
subsys   linux
va       true
```

Extração das strings e dos símbolos:
```shell
[0x000103bc]> fs strings
[0x000103bc]> f
0x00010610 9 str..S__f1CD
0x00010620 8 str.B_nn_1
0x00010628 9 str.Qml_6yD
0x00010638 9 str.XKfcj3TV
0x00010648 13 str.give_me_flag
0x00010658 13 str.correct_flag
0x00010668 11 str.wrong_flag
[0x000103bc]> fs symbols
[0x000103bc]> f
0x00010370 256 main
0x000103bc 62 entry0
0x0001046a 1 entry1.init
0x0001044c 1 entry2.fini
0x00012038 4 obj.i.2075
0x00012044 4 obj.i.2063
0x00012040 4 obj.i.2067
0x0001203c 4 obj.i.2071
0x000103fa 36 sym.deregister_tm_clones
0x0001041e 8 sym.register_tm_clones
0x0001044c 40 sym.__do_global_dtors_aux
0x00012048 1 obj.completed.5772
0x00011e28 0 obj.__do_global_dtors_aux_fini_array_entry
0x0001046a 0 sym.frame_dummy
0x00011e20 0 obj.__frame_dummy_init_array_entry
0x000106b8 0 obj.__FRAME_END
0x00010330 0 obj._PROCEDURE_LINKAGE_TABLE
0x00011e28 0 loc.__init_array_end
0x00011e30 0 obj._DYNAMIC
0x00011e20 0 loc.__init_array_start
0x00010678 0 loc.__GNU_EH_FRAME_HDR
0x00012020 0 obj._GLOBAL_OFFSET_TABLE
0x00010608 124 sym.__libc_csu_fini
0x00010560 152 sym.f2
0x00012000 0 loc.data_start
0x00012038 0 loc._edata
0x00012000 0 loc.__data_start
0x00010510 80 sym.f3
0x00012030 0 obj.__dso_handle
0x00012028 4 obj._IO_stdin_used
0x0001046e 81 sym.f1
0x000105b0 87 sym.__libc_csu_init
0x00012050 0 loc._end
0x000103bc 45 entry0
0x00012828 0 loc.__global_pointer
0x00012038 0 loc.__bss_start
0x00010370 16 sym.main
0x00012000 0 obj.__TMC_END
0x000104c0 80 sym.f4
```

Após algumas análises, identifiquei as funções interessantes e que precisam ser analisadas mais a fundo:
```
sym.main
sym.f1
sym.f2
sym.f3
sym.f4
```

Disassembly da sym.main com comentários:
```assembly_x86
/ (fcn) sym.main 16
|   sym.main ();
|           0x10370      addi sp, sp, -16
|           0x10372      sd ra, 8(sp)
|           0x10374      li a5, 2
|       ,=< 0x10376      beq a0, a5, 0x1038e
|       |   0x1037a      lui a0, 0x10
|       |   0x1037e      addi a0, a0, 1608 ; give me flag
        |   0x10382      auipc ra, 0x0
        |   0x10386      jalr -34(ra) ; imp.puts 0x10360
        |   0x1038a      li a0, 1
        |   0x1038c      j 0x103a8
        `-> 0x1038e      ld a0, 8(a1)
            0x10390      jal ra, sym.f1
            0x10394      beqz a0, 0x103ae
            0x10396      lui a0, 0x10
            0x1039a      addi a0, a0, 1624 ; correct flag
            0x1039e      auipc ra, 0x0
            0x103a2      jalr -62(ra)  ; imp.puts 0x10360
            0x103a6      li a0, 0
            0x103a8      ld ra, 8(sp)
            0x103aa      addi sp, sp, 16
            0x103ac      ret
            0x103ae      lui a0, 0x10
            0x103b2      addi a0, a0, 1640 ; wrong flag
            0x103b6      j 0x10382
            0x103b8      unimp
            0x103ba      unimp
```

A função main verifica a quantidade de paramêtros passados para o executável e se não tiver recebido paramêtro, printa `give me flag`. Caso tenha recebido o paramêtro, chama f1(paramêtro) e caso o retorno == 0, printa `wrong_flag`, caso retorno != 0 printa `correct flag`.

Main revertida para C:

```c
int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		puts("give me flag");
		return 1;
	}

	if (f1(argv[1]) == 0)
		puts("wrong flag");
	else
		puts("corretc flag");
}
```

Portanto a checagem da flag se inicia na função f1:

```assembly_x86
|   sym.f1 ();
|              ; UNKNOWN XREF from 0x10390 (main + 32)
|              ; CALL XREF from 0x10390 (main + 32)
|           0x1046e      lbu a5, 0(a0)
|           0x10472      beqz a5, 0x104bc
|           0x10474      addi sp, sp, -16
|           0x10476      sd s0, 0(sp)
|           0x10478      mv s0, a0
|           0x1047a      addi a0, a0, 1
|           0x1047c      sd ra, 8(sp)
|           0x1047e      auipc ra, 0x0
|           0x10482      jalr 226(ra) -> sym.f2
|           0x10486      li a5, 0
|           0x10488      beqz a0, 0x104b2
|           0x1048a      lui a4, 0x12
|           0x1048c      lw a5, 56(a4)
|           0x10490      lbu a0, 0(s0)
|           0x10494      addiw a3, a5, 1
|           0x10498      sw a3, 56(a4)
|           0x1049c      lui a4, 0x10
|           0x104a0      addi a4, a4, 1552 ; 0x00010610 str..S__f1CD
            0x104a4      add a5, a5, a4
            0x104a6      lbu a5, 0(a5)
            0x104aa      addiw a5, a5, -1
            0x104ac      sub a5, a5, a0
            0x104ae      seqz a5, a5
            0x104b2      ld ra, 8(sp)
            0x104b4      ld s0, 0(sp)
            0x104b6      mv a0, a5
            0x104b8      addi sp, sp, 16
            0x104ba      ret
            0x104bc      li a0, 0
            0x104be      ret
```

A função f1 checa 1 byte da string passada por paramêtro, passando o próximo byte para f2.

F1 revertida para C:

```c
int f1(char * arg)
{
	if (*arg == 0)
		return 0;

	char c = *arg;

	if (f2(++arg) == 0)
		return 0;

	if ((string_f1[index_f1++] - 1 - c) == 0)
		return 1;

	return 0;
}
```

As próximas funções são semelhantes, apenas alterando a string hardcoded e a operação para checagem (-2,+2,+1).

Código completo revertido para C:
```c
#include <stdio.h>

int f1(char * arg);
int f2(char * arg);
int f3(char * arg);
int f4(char * arg);

int index_f1 = 0;
char string_f1[9] = ".S``f1CD";

int index_f2 = 0;
char string_f2[9] = "XKfcj3TV";

int index_f3 = 0;
char string_f3[9] = "{Qml]6yD";

int index_f4 = 0;
char string_f4[9] = "B^nn^1,";

int f1(char * arg)
{
	if (*arg == 0)
		return 0;

	char c = *arg;

	if (f2(++arg) == 0)
		return 0;

	if ((string_f1[index_f1++] - 1 - c) == 0)
		return 1;

	return 0;
}

int f2(char * arg)
{
	if (*arg == 0)
		return 0;

	char c = *arg;

	if (f3(++arg) == 0)
		return 0;

	if ((string_f2[index_f2++] - 2 - c) == 0)
		return 1;

	return 0;
}

int f3(char * arg)
{
	if (*arg == 0)
		return 0;

	char c = *arg;

	if (f4(++arg) == 0)
		return 0;

	if ((string_f3[index_f3++] + 2 - c) == 0)
		return 1;

	return 0;
}

int f4(char * arg)
{
	if (*arg == 0)
		return 1;

	char c = *arg;

	if (f1(++arg) == 0)
		return 0;

	if ((string_f4[index_f4++] + 1 - c) == 0)
		return 1;

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		puts("give me flag");
		return 1;
	}

	if (f1(argv[1]) == 0)
		puts("wrong flag");
	else
		puts("corretc flag");
}
```

Assim, temos o código python para resolver a flag:

```python
f1 = [0x2E, 0x53, 0x60, 0x60, 0x66, 0x31, 0x43, 0x44]
f2 = [0x58, 0x4B, 0x66, 0x63, 0x6A, 0x33, 0x54, 0x56]
f3 = [0x7B, 0x51, 0x6D, 0x6C, 0x5D, 0x36, 0x79, 0x44]
f4 = [0x42, 0x5E, 0x6E, 0x6E, 0x5E, 0x31, 0x2C, 0x00]

flag = ''
for index in reversed(range(8)):
	flag += chr(f4[index] + 1) + chr(f1[index] - 1) + chr(f2[index] - 2) + chr(f3[index] + 2)

print flag
```

**CTF-BR{2018_eh_o_ano_do_RISC-V}**

