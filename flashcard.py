
import random




terms = """Affektiivinen sanavalinta.
allegoria
alluusio
analogia
denotaatio
ellipsi
epilogi
esisopimus
eufemismi
genre
hyperbola
kaikkitietävä kertoja
kehäpäätelmä
kerto
koheesio
konnotaatio
metafora
metonymia
narratiivinen
oksymoron
onomatopoeettinen
personifikaatio
retoriset keinot
synekdokeee
teema
aihe"""


defs = """tunteisiin vetoava sanavalinta.
vertauskuvallinen kertomus
intertekstuaalinen viittaus toiseen tekstiin
yhteneväinen ilmaisutapa tai esitystapa
sanan virallinen merkitys
osan poisjättäminen ilmauksesta merkityksen muuttumatta (Tyttö joi mehua ja lähti kouluun. (so. tyttö lähti kouluun))
loppukohtaus
oletus, että lukijalle jotkin asiat ovat esimerkiksi tuttuja entuudestaan
kaunisteleva kiertoilmaus
lajityyppi, tekstilaji
hieno sana liioittelulle
kertoja, joka tietää kaikesta kaiken
virheellinen päättelyketju, jossa johtopäätös on sama kuin väittämä
sama asia sanotaan monta kertaa eri sanoin
materiaalin sidosteisuus
sanalla on jokin lisämerkitys
kuvallinen ilmaus
kielikuva, josssa ilmaus on korvattu läheisellä termillä
kertova
kahden näennäisesti vastakohtaisen käsitteen yhdistäminen
sana, joka mukailee jotain ääntää (piipittää, rasahtaa)
elottoman elollistaminen
argumentatiivisen tekstin kielelliset tehokeinot
yleinen esittää yksityistä tai yksittäinen yleistä (ihminen astui kuuhun = ihmiskunta valloitti kuun)
tekstin perusajatus
mistä teksti kertoo."""




if __name__=="__main__":
	terms_list = terms.split("\n")
	defs_list = defs.split("\n")
	while True:
		

		random_thing = random.randrange(0, len(terms_list))
		which_first = random.randrange(0,2)

		if which_first==0:

			print("=================")
			print(terms_list[random_thing])
			input()
			print(defs_list[random_thing])
			print("=================")
		else:
			print("=================")
			print(defs_list[random_thing])
			input()
			print(terms_list[random_thing])
			print("=================")







