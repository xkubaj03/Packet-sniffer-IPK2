# IPK projekt 2 - varianta ZETA: Sniffer paketů
Sniffer paketů zachytává pakety na určitém rozhraní a vypisuje čas přijetí, zdrojovou mac adresu, cílovou mac adresu, délku packetu v bytech (a pokud to pakety obsahují tak i zdrojovou ip adresu, cílovou ip adresu, zdrojový port a cílový port).

## Přepínače 
- -i / --interface Přepínač má argument volitelný. Pokud není zadán vypíše seznam aktivních rozhraní. Jinak očekává název rozhraní na kterém bude zachytávat pakety.
- -p Přepínač má povinný argument, který udává číslo portu na němž se budou zachytávat pakety.
- -n Přepínač má povinný argument, který udává počet zachycovaných paketů.
- -t / --tcp Přepínač nemá argument. Značí, že se budou zachytávat TCP pakety.
- -u / --udp Přepínač nemá argument. Značí, že se budou zachytávat UDP pakety.
- --arp Přepínač nemá argument. Značí, že se budou zachytávat ARP pakety.
- --icmp Přepínač nemá argument. Značí, že se budou zachytávat ICMPv4 a ICMPv6 pakety.
- Pokud nebudou konkrétní protokoly specifikovány, uvažují se k tisknutí všechny (tj. veškerý obsah, nehledě na protokol)

## Příklady spuštění
- $ sudo ./ipk-sniffer -i enp0s3 -p 80 -n 10 -udp
- $ sudo ./ipk-sniffer --interface enp0s3 -n 10
- $ sudo ./ipk-sniffer --interface enp0s3 --udp --tcp --arp --icmp
- $ sudo ./ipk-sniffer --interface enp0s3  (stejné jako předchozí příklad)
- $ sudo ./ipk-sniffer -i

## Seznam odevzdaných souborů
1. ipk-sniffer.c
2. Makefile
3. README.md

