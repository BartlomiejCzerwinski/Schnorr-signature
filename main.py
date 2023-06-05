import random
import hashlib
import sympy
import tkinter as tk

S1 = 0
S2 = 0

def generatePQ():
    q = get_random_prime(141)
    p = get_p_based_on_q(q, 513)
    p_entry.delete(0, tk.END)
    p_entry.insert(0, p)
    q_entry.delete(0, tk.END)
    q_entry.insert(0, q)
    return

def get_random_prime(bit_length):
    result = 0
    while True:
        result = get_random_positive_number(bit_length)
        if result < (2**140) or result % 2 == 0 or not sympy.isprime(result):
            continue
        return result
def get_p_based_on_q(q, bits_magnitude):
    p = 0
    while True:
        r = get_random_positive_number(bits_magnitude - q.bit_length())
        p = (q * r) + 1
        if p % 2 == 0 or not sympy.isprime(p):
            continue
        return p

def get_random_positive_number(bits):
    return random.randint(2**(bits), 2**(bits + 1))

def modular_inverse(a, modulus):
    _, x, _ = extended_gcd(a, modulus)
    return x % modulus

def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    else:
        d, x, y = extended_gcd(b, a % b)
        return d, y, x - (a // b) * y

def generateH():
    p = int(p_entry.get())
    q = int(q_entry.get())
    h = pow(2, (p-1) // q, p)
    if pow(h, q, p) != 1:
        return None
    h_entry.delete(0, tk.END)
    h_entry.insert(0, h)
    return h

def generatePublicKey():
    h = int(h_entry.get())
    a = int(private_key_entry.get())
    p = int(p_entry.get())
    v = modular_inverse(pow(h, a, p), p)
    public_key_entry.delete(0, tk.END)
    public_key_entry.insert(0, v)
    return v

def generatePrivateKey():
    a = random.randint(2, p - 1)
    private_key_entry.delete(0, tk.END)
    private_key_entry.insert(0, a)

p = 14047760943752938361746919685995658907281676870599135871164059239050932509273452217143486842924701564060027713870107807538192349039155876547246137978426179
q = 58352546340205099687803049242117173270346075125618347517898233102732326091947960809688761824801971195288667806683920485143954665647

def loadDataFromFile():
    try:
        with open(loadText_entry.get(), "rb") as file:
            text = file.read()
            binary_str = ''.join(format(byte, '08b') for byte in text)
            texty_entry.delete(0, tk.END)
            texty_entry.insert(0, text)
            file.close()
            return binary_str
    except FileNotFoundError:
        print("File doesn't exist")

def split_string(string):
    global S1, S2
    S1, S2 = string.split(',', 1) if ',' in string else (string, '')
    S1 = int(S1)
    S2 = int(S2)

def generateSignature():
    p = int(p_entry.get())
    q = int(q_entry.get())
    h = int(h_entry.get())
    a = int(private_key_entry.get())
    r = random.randint(1, q - 1)
    X = pow(h, r, p)
    X_bytes = X.to_bytes((X.bit_length() + 7) // 8, byteorder='big')
    M = texty_entry.get().encode('utf-8')
    hash_object = hashlib.sha256(M + X_bytes)
    hash_value = hash_object.digest()
    s1 = int.from_bytes(hash_value, byteorder='big')
    global S1, S2
    s2 = (r + a * s1) % q
    S1 = int(s1)
    S2 = int(s2)
    signature = str(s1) + "," + str(s2)
    signature_entry.delete(0, tk.END)
    signature_entry.insert(0, signature)

def verifySignature():
    global S1, s2
    p = int(p_entry.get())
    h = int(h_entry.get())
    v = int(public_key_entry.get())
    Z = (pow(h, S2, p) * pow(v, S1, p)) % p
    Z_bytes = Z.to_bytes((Z.bit_length() + 7) // 8, byteorder='big')
    M = texty_entry.get().encode('utf-8')
    hash_object = hashlib.sha256(M + Z_bytes)
    hash_value = hash_object.digest()
    split_string(signature_entry.get())
    if int.from_bytes(hash_value, byteorder='big') == S1:
        signature_verify_entry.delete(0, tk.END)
        signature_verify_entry.insert(0, "PRAWDA")
    else:
        signature_verify_entry.delete(0, tk.END)
        signature_verify_entry.insert(0, "FAŁSZ")


root = tk.Tk()
root.geometry("900x600")

key_frame = tk.Frame(root, bd=2, relief=tk.RAISED)
key_frame.place(x=250, y=0)

inner_frame = tk.Frame(key_frame)
inner_frame.pack(expand=True, fill=tk.BOTH, padx=50, pady=50)

textk_label = tk.Label(inner_frame, text="p q h")
textk_label.grid(row=0, column=1)

key_label = tk.Label(inner_frame, text="p:", font=("Aerial", 8))
key_label.grid(row=1, column=0)

p_entry = tk.Entry(inner_frame, width=15, font=("Arial", 8))
p_entry.grid(row=1, column=1)

p_entry.bind("<Key>", lambda e: "break")
p_entry.insert(0, p);

generate_p_q_button = tk.Button(inner_frame, text="Generuj p q", font=("Arial", 8), command=generatePQ)
generate_p_q_button.grid(row=1, column=2, padx=10)

loadKey_label = tk.Label(inner_frame, text="q:", font=("Aerial", 8))
loadKey_label.grid(row=2, column=0)

q_entry = tk.Entry(inner_frame, width=15, font=("Aerial", 8))
q_entry.grid(row=2, column=1)
q_entry.insert(0, q)

saveKey_label = tk.Label(inner_frame, text="h:", font=("Aerial", 8))
saveKey_label.grid(row=3, column=0)

h_entry = tk.Entry(inner_frame, width=15, font=("Aerial", 8))
h_entry.grid(row=3, column=1)

generate_h_button = tk.Button(inner_frame, text="Generuj h", font=("Arial", 8), command=generateH)
generate_h_button.grid(row=3, column=2, padx=10)

sd_frame = tk.Frame(root, bd=2, relief=tk.RAISED)
sd_frame.place(x=100 , y=200)

inner2_frame = tk.Frame(sd_frame)
inner2_frame.pack(expand=True, fill=tk.BOTH, padx=50, pady=50)

textz_label = tk.Label(inner2_frame, text="Podpisz / Zweryfikuj podpis")
textz_label.grid(row=0, column=0)

loadText_label = tk.Label(inner2_frame, text="Załaduj dane z pliku:", font=("Aerial", 8))
loadText_label.grid(row=1, column=0)

loadText_entry = tk.Entry(inner2_frame, width=15, font=("Aerial", 8))
loadText_entry.grid(row=2, column=0)

loadText_button = tk.Button(inner2_frame, text="Załaduj", font=("Arial", 8), command=loadDataFromFile)
loadText_button.grid(row=3, column=0, pady=10)

loadCiphertext_label = tk.Label(inner2_frame, text="Klucz prywatny:", font=("Aerial", 8))
loadCiphertext_label.grid(row=1, column=1)

private_key_entry = tk.Entry(inner2_frame, width=15, font=("Aerial", 8))
private_key_entry.grid(row=2, column=1)

generate_private_key_button = tk.Button(inner2_frame, text="Generuj klucz prywatny", font=("Arial", 8), command=generatePrivateKey)
generate_private_key_button.grid(row=3, column=1, pady=10)

saveText_label = tk.Label(inner2_frame, text="Klucz publiczny:", font=("Aerial", 8))
saveText_label.grid(row=1, column=2)

public_key_entry = tk.Entry(inner2_frame, width=15, font=("Aerial", 8))
public_key_entry.grid(row=2, column=2)

saveText_button = tk.Button(inner2_frame, text="Generuj klucz publiczny", font=("Arial", 8), command=generatePublicKey)
saveText_button.grid(row=3, column=2, pady=10)

saveCiphertext_label = tk.Label(inner2_frame, text="Podpis prawdziwy", font=("Aerial", 8))
saveCiphertext_label.grid(row=1, column=3)

signature_verify_entry = tk.Entry(inner2_frame, width=15, font=("Aerial", 8))
signature_verify_entry.grid(row=2, column=3)

texty_label = tk.Label(inner2_frame, text="Dane:", font=("Aerial", 8))
texty_label.grid(row=4, column=0)

texty_entry = tk.Entry(inner2_frame, width=30, font=("Aerial", 8))
texty_entry.grid(row=5, column=0)

texty_button = tk.Button(inner2_frame, text="Podpisz", font=("Arial", 8), command=generateSignature)
texty_button.grid(row=5, column=1)

ciphertext_label = tk.Label(inner2_frame, text="Podpis:", font=("Aerial", 8))
ciphertext_label.grid(row=4, column=3)

signature_entry = tk.Entry(inner2_frame, width=30, font=("Aerial", 8))
signature_entry.grid(row=5, column=3)

ciphertext_button = tk.Button(inner2_frame, text="Weryfikuj podpis", font=("Arial", 8), command=verifySignature)
ciphertext_button.grid(row=5, column=2, padx=10)

root.mainloop()
