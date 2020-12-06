Cortar por posição de byte (2o byte): 
$ echo 'baz' | cut -b 2

Cortar por posição de byte (1o e 2o bytes): 
echo 'baz' | cut -b 1-2

Cortar por posição de byte (1o e 3o bytes): 
$ echo 'baz' | cut -b 1,3

Cortar por posição de caracter (2o byte): 
$ echo '@foobar' | cut -b 2

Cortar por posição de byte (1o até 4o bytes): 
echo '@foobar' | cut -b 1-4

Cortar com base em um delimitador ',' (primeira coluna):
$ cut -d ',' -f 1 nomes.csv

Cortar com base em um delimitador ',' (primeira e quarta coluna):
$ cut -d ',' -f 1,4 nomes.csv
 
Cortar complemento: 
$ echo 'foo' | cut --complement -c 1

Modificar o delimitador de saída (; para ,):
$ echo 'how;now;brown;cow' | cut -d ';' -f 1,3,4 --output-delimiter=','