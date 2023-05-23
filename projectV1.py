
from scapy.all import sniff ,Ether,IP

def paket_ayiklayici(paket):
    if IP in paket:
        #mac ve ip adresini sniff fonksiyonun icersinde paket[].src ile cekiyoruz.
        mac_adresi = paket[Ether].src
        ip_adresi = paket[IP].src
        #ip_adresi_dst = paket[IP].dst
        print("source mac Adresi: ", mac_adresi)
        print("source ip Adresi: ", ip_adresi)
        #print("destination ip Adresi: ", ip_adresi1)
        #dosya yazdiriliyor.
        with open("mac_and_ip.txt", "a") as dosya:
            dosya.write("source mac Adresi: "+mac_adresi + " & ")
            dosya.write("source ip Adresi: "+ip_adresi + "\n")
sniff(prn=paket_ayiklayici, store=0,count=0)


#sniff() fonksiyonu agi direkt kendisi butun paketleri tarar.Ve hepsini geri
#dondurur.Bizim bu paketlerin arasinda isimize yarayacak seyleri duzgun
#bir bicimde almamiz gerekiyor.
#a=sniff(count=2,prn=lambda x:x.show())
#a.show()
#bu kisim demek istedigim yeri guzelce gosteriyor.
