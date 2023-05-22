import random
import hashlib
import sympy

def generatePQ():
    while True:
        p = sympy.randprime(2 ** 512, 2 ** 513)  # Generowanie losowej liczby pierwszej z zakresu 2^512 - 2^513
        factors = sympy.factorint(p - 1)  # Faktoryzacja (p-1)
        print(sympy.isprime(p))
        for q in factors:
            if q > 2 ** 140:  # Sprawdzanie warunku q > 2^140
                return p, q

def modular_inverse(a, modulus):
    _, x, _ = extended_gcd(a, modulus)
    return x % modulus

def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    else:
        d, x, y = extended_gcd(b, a % b)
        return d, y, x - (a // b) * y

def find_h(p, q):
    h = pow(2, (p-1) // q, p)
    if pow(h, q, p) != 1:
        return None
    return h

def calculate_v(h, a, p):
    v = modular_inverse(pow(h, a, p), p)
    return v

p = 14047760943752938361746919685995658907281676870599135871164059239050932509273452217143486842924701564060027713870107807538192349039155876547246137978426179
q = 58352546340205099687803049242117173270346075125618347517898233102732326091947960809688761824801971195288667806683920485143954665647
#p, q = generatePQ()
print(f"Liczba pierwsza p: {p}")
print(f"Wartość q dla liczby p: {q}")
h = find_h(p, q)
print("h: ", h)
a = random.randint(2, p-1) # klucz prywatny
print("klucz prywatny:  ", a)
v = pow(h, -a, p)
print("v: ", v)
v2 = calculate_v(h, a, p)
print("klucz publiczny: ", v2)

#generowanie podpisu
r = random.randint(1, q-1)
X = pow(h, r, p)

X_bytes = X.to_bytes((X.bit_length() + 7) // 8, byteorder='big')  # Konwersja wartości X na bajty

hash_object = hashlib.sha256(X_bytes)  # Utworzenie obiektu haszującego dla algorytmu SHA-256
hash_value = hash_object.digest()  # Obliczenie skrótu w postaci bajtowej (bytes)
s1 = int.from_bytes(hash_value, byteorder='big')
print("Wartość skrótu (dec):", s1)
s2 = (r + a*s1) % q
print("s2: ", s2)
Z = (pow(h, s2, p) * pow(v, s1, p)) % p

Z_bytes = Z.to_bytes((Z.bit_length() + 7) // 8, byteorder='big')  # Konwersja wartości X na bajty
hash_object2 = hashlib.sha256(Z_bytes)  # Utworzenie obiektu haszującego dla algorytmu SHA-256
hash_value2 = hash_object2.digest()  # Obliczenie skrótu w postaci bajtowej (bytes)
res = int.from_bytes(hash_value2, byteorder='big')
print("Wartość wyniku (dec):", res)

with open('test.txt', 'rb') as file:
    document_data = file.read()

signed_document = document_data + s1.to_bytes((s1.bit_length() + 7) // 8, byteorder='big') + s2.to_bytes((s2.bit_length() + 7) // 8, byteorder='big')

with open('podpisany_dokument.txt', 'wb') as file:
    file.write(signed_document)

