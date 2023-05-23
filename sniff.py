from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.all import *

a=sniff(count=8,store=0,prn=lambda x:x.show())
a.show()

#burda anlasilan sey
#sniff() fonksiyonu agi direkt kendisi butun paketleri tarar.Ve hepsini geri
#dondurur.Bizim bu paketlerin arasinda isimize yarayacak seyleri duzgun
#bir bicimde almamiz gerekiyor.
#a=sniff(count=2,prn=lambda x:x.show())
#a.show()
#bu kisim demek istedigim yeri guzelce gosteriyor.
