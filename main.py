#------------------------------------------------------------------
#------------------Berkay Bakışoğlu--------------------------------
#--------------------141044061-------------------------------------
#128,192,256 AES algoritması,CBC ve OFB modları kullanılarak gerçeklendi.
#Kimlik doğrulama için AES'in CBC modu kullanılarak,veri şifrelenerek dosyaya yazıldı.
#Yazılan bu şifreden sonra dosya üzerinde değişiklik yapılıp yapılmadığı,dosyanın şifre yazmayan kısmı yine AES-CBC ile gerçeklenerek,dosya sonunda yazılmış
#doğrulama anahtarı ile uyumlu olup olmadığı kontrol edildi.
zeroIV = "0000000000000000".encode('utf-8')
turSayisi = 0
anahtarMatrisi = []
Rcon = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D,
        0x9A)  # 14 = 256 12 = 192 10 = 128
Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

RSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)
#Anahtar sayısının uzunluğuna göre tur sayısını atar ve anahtar genişletimini başlatır.
def turSayisiGenisletilmisAnahtarAta(anahtar):
    global turSayisi
    global anahtarMatrisi
    if len(anahtar) == 16:
        turSayisi = 10
    elif len(anahtar) == 24:
        turSayisi = 12
    elif len(anahtar) == 32:
        turSayisi = 14
    else:
        print("anahtar uzunlugu 16,24 veya 32 olmalıdır,program kapanıyor!")
        exit()
    anahtarMatrisi = anahtarGenisletimi(anahtar)
#Anahtar genişletimi algoritması
def anahtarGenisletimi(anahtar):
    genisletilmisAnahtar = convertToMatrix(anahtar)
    i = 1
    #Nb(Nr + 1)
    N=(turSayisi + 1) * 4
    Nr = len(anahtar) // 4
    while len(genisletilmisAnahtar) < N:
        parca = list(genisletilmisAnahtar[-1]) #genisletilmis anahtarın son sırası alınır
        if len(genisletilmisAnahtar) % Nr == 0: #Eger 4 ün katı ise
            parca.append(parca.pop(0)) #dairesel kaydırma uygulanır
            parca = [Sbox[b] for b in parca] #kolonun byteları değiştirilir.
            parca[0] ^= Rcon[i] #kolon Rconla xorlanır
            i += 1
        parca = ByteXor(parca, genisletilmisAnahtar[-Nr]) #genisletilmis anahtarın -NR sırasıyla,parça xorlanarak genisletilmis anahtara eklenir.
        genisletilmisAnahtar.append(parca)
    return [genisletilmisAnahtar[4 * i: 4 * (i + 1)] for i in range(len(genisletilmisAnahtar) // 4)]
#Girdi olarak alınan dizi,matrise dönüştürülür.
def convertToMatrix(text):
    matris = []
    for i in range(0, len(text), 4):
        matris.append(list(text[i:i + 4]))
    return matris

#Girdi olarak alınan matris,byte listesine dönüşür.
def duzMatris(matris):
    duzMatris = sum(matris, [])
    return bytes(duzMatris)
#Girdi olarak alınan 2 matrisin öğeleri üzerinde xor işlemi uygulanır.
def ByteXor(x, y):
    xored = []
    byteCiftleri = zip(x,y)
    for i, j in byteCiftleri:
        xored.append(i ^ j)
    return bytes(xored)
#Aes tur öncesi: S modu için aes algoritmasının başlangıcı,R modu için algoritmanın son basamağı
def AESTurOncesi(durumMatrisi, mod):
    if mod == 'S':
        turAnahtariEkle(durumMatrisi, anahtarMatrisi[0])
    elif mod == 'R':
        turAnahtariEkle(durumMatrisi, anahtarMatrisi[0])
    return durumMatrisi

#Aes tur algoritması: sifreleme için,bytelar yer değiştirilir,matris kaydırmaları gerçeklenir,satırlar karıştırılır ve tur anahtarı eklenir.
#Sifre kırma için bu işlemler ters sırada yapılır.
def AESTur(durumMatrisi, mod, tur):
    if mod == 'S':
        byteDegistir(durumMatrisi, 'S')
        solaKaydir(durumMatrisi)
        satirlariKaristir(durumMatrisi)
        turAnahtariEkle(durumMatrisi, anahtarMatrisi[tur])
    elif mod == 'R':
        turAnahtariEkle(durumMatrisi, anahtarMatrisi[tur])
        tersSatirlariKaristir(durumMatrisi)
        geriKaydir(durumMatrisi)
        byteDegistir(durumMatrisi, 'R')
    return durumMatrisi

#Aes son tur algoritması,sifreleme için bytelar yer degistirilir,kaydırma işlemi gerçeklenir,tur anahtarı son kez eklenir:
    #Şifre kırma için bu işlemler tersten uygulanır
def AESSonTur(durumMatrisi, mod):
    if mod == 'S':
        byteDegistir(durumMatrisi, 'S')
        solaKaydir(durumMatrisi)
        turAnahtariEkle(durumMatrisi, anahtarMatrisi[len(anahtarMatrisi) - 1])
    elif mod == 'R':
        turAnahtariEkle(durumMatrisi, anahtarMatrisi[len(anahtarMatrisi) - 1])
        geriKaydir(durumMatrisi)
        byteDegistir(durumMatrisi, 'R')
    return durumMatrisi

#Konum matrisinin elementlerini anahtar ile xorlar
def turAnahtariEkle(durumMatrisi, anahtar):
    for i in range(4):
        for j in range(4):
            durumMatrisi[i][j] ^= anahtar[i][j]
    return durumMatrisi

#Byte yer değiştirmelerini,sifreleme için s,sifre kırma için r modlarında çalışarak gerceklestirir.
def byteDegistir(durumMatrisi, mod):
    for i in range(4):
        for j in range(4):
            if mod == "S":
                durumMatrisi[i][j] = Sbox[durumMatrisi[i][j]]
            elif mod == "R":
                durumMatrisi[i][j] = RSbox[durumMatrisi[i][j]]

#Blok şifreleme için girdiyi 16nın katı olacak sekilde uzatır.
def genislet(girdi):
    genislemeUzunlugu = 16 - (len(girdi) % 16)
    ek = bytes([genislemeUzunlugu] * genislemeUzunlugu)
    return girdi + ek

#Genisletme islemi uygulanmış veriyi ilk haline cevirir.
def daralt(girdi):
    genislemeUzunlugu = girdi[len(girdi) - 1]
    return girdi[:len(girdi) - genislemeUzunlugu]

#Gelen veriyi 16 bitlik bloklara ayırır.
def bloklaraAyır(veri):
    bloklistesi = []
    for i in range(0, len(veri), 16):
        bloklistesi.append(veri[i:i + 16])
    return bloklistesi

#Satırların kaydırma işlemi uygulanır
def solaKaydir(s):  # Satır 0 değişmez
    # 1.Satır >> 1 sola
    gecici = s[1][0]
    s[1][0] = s[1][1]
    s[1][1] = s[1][2]
    s[1][2] = s[1][3]
    s[1][3] = gecici
    # 2.Satır >> 2 sola
    gecici = s[2][0]
    s[2][0] = s[2][2]
    s[2][2] = gecici
    gecici = s[2][1]
    s[2][1] = s[2][3]
    s[2][3] = gecici
    # 3.Satır >> 3 sola
    gecici = s[3][0]
    s[3][0] = s[3][3]
    s[3][3] = s[3][2]
    s[3][2] = s[3][1]
    s[3][1] = gecici
#Kaydırılmış satırlar eski haline getirilir
def geriKaydir(s): # Satır 0 değişmez
    # 1.Satır >> 1 sağa
    gecici=s[1][3]
    s[1][3] = s[1][2]
    s[1][2] = s[1][1]
    s[1][1] = s[1][0]
    s[1][0] = gecici
    # 2.Satır >> 2sağa
    gecici=s[2][3]
    s[2][3] = s[2][1]
    s[2][1]=gecici
    gecici = s[2][2]
    s[2][2] = s[2][0]
    s[2][0]=gecici
    # 3.Satır >> 3 sağa
    gecici = s[3][1]
    s[3][1] = s[3][2]
    s[3][2] = s[3][3]
    s[3][3] = s[3][0]
    s[3][0]=gecici
# http://www.nic.funet.fi/~bande/docs/crypt/system/Rijndaeldoc.pdf
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)
#Galois Algoritması gerçeklenir.
def satirlariKaristir(s):
    for i in range(4):
        t = s[i][0] ^ s[i][1] ^ s[i][2] ^ s[i][3]
        u = s[i][0]
        s[i][0] ^= t ^ xtime(s[i][0] ^ s[i][1])
        s[i][1] ^= t ^ xtime(s[i][1] ^ s[i][2])
        s[i][2] ^= t ^ xtime(s[i][2] ^ s[i][3])
        s[i][3] ^= t ^ xtime(s[i][3] ^ u)
#Galois Algoritması tersten gerçeklenir.
def tersSatirlariKaristir(s):
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][2] ^= u
        s[i][1] ^= v
        s[i][3] ^= v
    satirlariKaristir(s)

#Gönderilen mesaj,anahtar kullanılarak CBC Veya OFB modlarında sifrelenir.isMAC parametresi 1 olduğunda,dosya sifreleme kontrolu için AES-CBC'nin son blogu özüt olarak gönderilir.
def sifrele(mesaj, mod, isMAC=0, IV=zeroIV):
    sifrelenmisBloklar = []
    sonBlok = IV
    if mod == "CBC":
        mesaj = genislet(mesaj)
    for islenenBlok in bloklaraAyır(mesaj):
        if mod == "CBC":
            cozulmusBlok = blokSifreleme(ByteXor(islenenBlok, sonBlok))
            sifrelenmisBloklar.append(cozulmusBlok)
        elif mod == "OFB":
            cozulmusBlok = blokSifreleme(sonBlok)
            sifreliBlok = ByteXor(islenenBlok, cozulmusBlok)
            sifrelenmisBloklar.append(sifreliBlok)
        else:
            return 0
        sonBlok = cozulmusBlok
    if isMAC == 1:
        return sonBlok
    return b''.join(sifrelenmisBloklar)

#CBC veya OFB modları kullanılarak,sifreli yazinin her bloğu için gerekli islem yapılarak blokların şifresi çözülür.
def sifreCoz(sifreliYazi, mod, IV=zeroIV):
    bloklar = []
    sonBlok = IV
    for sifreliBlok in bloklaraAyır(sifreliYazi):
        if mod == "CBC":
            bloklar.append(ByteXor(sonBlok, blokSifresiniCoz(sifreliBlok)))
            sonBlok = sifreliBlok
        elif mod == "OFB":
            blok = blokSifreleme(sonBlok)
            duzyaziBlok = ByteXor(sifreliBlok, blok)
            bloklar.append(duzyaziBlok)
            sonBlok = blok
    if mod == "CBC":
        return daralt(b''.join(bloklar))
    elif mod == "OFB":
        return b''.join(bloklar)

#Alınan bir blok AES algoritması kullanılarak şifrelenir.
def blokSifreleme(duzyazi):
    duzKonumlar = AESTurOncesi(convertToMatrix(duzyazi), 'S')
    for i in range(1, turSayisi):
        AESTur(duzKonumlar, 'S', i)
    return duzMatris(AESSonTur(duzKonumlar, 'S'))

#Alınan bir blogun AES algoritması kullanılarak şifresi cözülür.
def blokSifresiniCoz(sifreliyazi):
    sifreliKonumlar = AESSonTur(convertToMatrix(sifreliyazi), 'R')
    for i in range((turSayisi - 1), 0, -1):
        sifreliKonumlar = AESTur(sifreliKonumlar, 'R', i)
    sifreliKonumlar = AESTurOncesi(sifreliKonumlar, 'R')
    return duzMatris(sifreliKonumlar)
#Dosyayı byte byte okur
def dosyaOkuma(dosyaAdi):
    liste = []
    with open(dosyaAdi, "rb") as file:
        while True:
            byte = file.read(1)
            if not byte:
                break
            liste.append(byte)
    return b''.join(liste)
#Dosyaya byteları yazar
def dosyayaYaz(dosyaAdi,girdi):
    with open(dosyaAdi, "ab") as file:
        file.write(girdi)
    file.close()
#AES algoritması kullanarak okunan dosyanın özütünü alır,daha sonra bu özütü dosyanın sonuna ekler
def dogrulamayiYaz(dosyaAdi, anahtar):
    okunanDosya = dosyaOkuma(dosyaAdi)
    turSayisiGenisletilmisAnahtarAta(anahtar)
    MAC = sifrele(okunanDosya, "CBC", 1)
    dosyayaYaz(dosyaAdi, MAC)
    return MAC
#AES algoritması kullanılarak,dosya okunur ve okunan dosyanın son 16 byte hariç özütü alınır,bu özüt son 16 byte da bulunan sifreyle karşılaştırılır:
#Eger son 16 bayt ve özüt aynı ise,dosya üzerinde degisiklik yapılmamıştır,
#Eger aynı değillerse dosya degistirilmiştir.
def dogrulamaKontrolu(dosyaAdi, anahtar):
    okunanDosya = dosyaOkuma("test")
    MAC = sifrele(okunanDosya[:-16], "CBC", 1)
    dogrulama=okunanDosya[len(okunanDosya)-16:]
    if dogrulama == MAC:
        print("Dosya şifrelendiğinden beri değişmedi")
        return 1
    print("Dosya şifrelendikten sonra değişikliğe uğramıs")
    return 0


def test1(): # OFB Ile sifreleme 16 byte anahtar
    anahtar = "BirinciTestIcin1".encode('utf-8')
    mesaj = "BirinciTestinGerceklenmesindeKullanilacakMesaj".encode('utf-8')
    IV = "1234567891234567".encode('utf-8')
    turSayisiGenisletilmisAnahtarAta(anahtar)
    print("--------------------------TEST1--------------------------")
    print(mesaj, " OBF ile 16 byte anahtar",anahtar,"kullanılarak sifrelenecek ")
    ilkSifreleme = sifrele(mesaj, "OFB", 0, IV)
    print("Sifreli mesaj : ", ilkSifreleme)
    ilkCozulmus = sifreCoz(ilkSifreleme, 'OFB', IV)
    print("Cözülmüs mesaj : ", ilkCozulmus)


def test2(): # CBC Ile sifreleme 32 byte anahtar
    anahtar = "IkinciTestIcinIkinciTestIcin2222".encode('utf-8')
    mesaj = "IkinciIkinciIkinciIkinciIkinciIkinciIkinciTestTestTestTestIcinIcinIcinIcin".encode('utf-8')
    IV = "1234567891234567".encode('utf-8')
    turSayisiGenisletilmisAnahtarAta(anahtar)

    print("--------------------------TEST2--------------------------")
    print(mesaj, " CBC ile 32 byte anahtar",anahtar,"kullanılarak sifrelenecek ")
    ikinciSifreleme = sifrele(mesaj, "CBC", 0, IV)
    print("Sifrelenen Mesaj : ", ikinciSifreleme)
    ilkCozulmus = sifreCoz(ikinciSifreleme, 'CBC', IV)
    print("Cözülmüs mesaj : ", ilkCozulmus)
    print("-------------------")


def test3():
    anahtar = "ThisIsThirdTest3".encode('utf-8')
    mesaj = "ThisIsTheFirstMessage".encode('utf-8')
    dosyaAdi="test"
    print("--------------------------TEST3--------------------------")
    yazilmisDogrulamaKodu = dogrulamayiYaz(dosyaAdi, anahtar)
    print("Dogrulama kodu = ",yazilmisDogrulamaKodu," dosyaya eklendi")
    print("Bu kod kullanılarak dogrulama kontrolu yapılıyor: ",yazilmisDogrulamaKodu)
    test4(dosyaAdi,anahtar,yazilmisDogrulamaKodu)
    print("Dosya üzerinde değişiklik yapılıyor")
    dosyayaYaz(dosyaAdi,mesaj)
    print("Bu kod kullanılarak dogrulama kontrolu yapılıyor: ", yazilmisDogrulamaKodu)
    test5(dosyaAdi,anahtar,yazilmisDogrulamaKodu)
def test4(dosyaAdi,anahtar,yazilmisDogrulamaKodu):
    print("--------------------------TEST4--------------------------")
    dogrulamaKontrolu(dosyaAdi, anahtar)
def test5(dosyaAdi, anahtar, yazilmisDogrulamaKodu):
    print("--------------------------TEST5--------------------------")
    dogrulamaKontrolu(dosyaAdi, anahtar)

if __name__ == '__main__':
    test1()
    test2()
    test3() ## test 4 ve test 5i de içerir
