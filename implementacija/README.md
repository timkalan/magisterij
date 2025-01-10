# Primerjava podpisov

V tej mapi se nahajajo implementacije navadnega Schnorrovega podpisa, večstranskega ASM podpisa
in večstranskega MuSig2 podpisa. Poleg tega se nahaja tudi primerjava njihove hitrosti, s ciljem
videti koliko ljudi mora sodelovati pri skupinskem podpisu, da je potrebnega manj dela, kot če bi
se enostavno vsak član skupine individualno podpisal.

## Poganjanje preizkusov

Da preverimo hitrost podpisovanja, se postavimo v mapo `implementacija/` in poženemo
```
go test -bench=. ./PODPIS
```
Za osnovne teste. Če nas zanima še poraba spomina, poženemo
```
go test -bench=. -benchmem ./PODPIS
```
Če pa želimo natančneje analizirati uporabo procesorja, lahko poženemo
```
go test -bench=. -cpuprofile cpu.out ./PODPIS
go tool pprof cpu.out
```
kjer `PODPIS` nadomestimo z ustreznim imenom mape (npr. `schnorr`).

## Potencialna vprašanja
- Koliko časa traja ustvarjanje/preverjanje $n$ individualnih podpisov v primerjavi z večstranskim
podpisom skupine velikosti $n$?
- Koliko podpisov je lahko ustvarjenih/preverjenih na sekundo?
- Koliko časa traja ustvarjanje večstranskega podpisa v odvisnosti od $n$ (in primerjava z navadnim
podpisom)?
- Komunikacija: Kako vpliva? Kako jo simuliramo?
- Energetska učinkovitost v odvisnosti od $n$.
- Poraba spomina.
- Odpornost na napake.

## Opombe
- Rezultate preizkusov lahko primerjamo z `benchstat`.
