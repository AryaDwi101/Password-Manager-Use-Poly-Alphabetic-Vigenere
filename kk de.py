import tkinter as tk
from tkinter import messagebox

# --- BAGIAN 1: LOGIKA VIGENERE ---

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+? "

def vigenere_encrypt(plain_text, key):
    encrypted_text = ""
    key_index = 0
    
    for char in plain_text:
        if char in ALPHABET:
            p_index = ALPHABET.index(char)
            k_char = key[key_index % len(key)]
            k_index = ALPHABET.index(k_char)
            
            cipher_index = (p_index + k_index) % len(ALPHABET)
            
            encrypted_text += ALPHABET[cipher_index]
            key_index += 1
        else:
            encrypted_text += char
            
    return encrypted_text

def vigenere_decrypt(cipher_text, key):
    decrypted_text = ""
    key_index = 0
    
    for char in cipher_text:
        if char in ALPHABET:
            c_index = ALPHABET.index(char)
            k_char = key[key_index % len(key)]
            k_index = ALPHABET.index(k_char)
            
            plain_index = (c_index - k_index) % len(ALPHABET)
            
            decrypted_text += ALPHABET[plain_index]
            key_index += 1
        else:
            decrypted_text += char
            
    return decrypted_text

# --- BAGIAN 2: FUNGSI GUI ---

def generate_password():
    service = entry_service.get()
    username = entry_username.get()
    master_key = entry_key.get()

    if not service or not username or not master_key:
        messagebox.showerror("Error", "Mohon isi semua kolom!")
        return

    # Sisipkan tanda + sebagai pemisah antara layanan dan username
    raw_data = service + "+" + username
    
    password_result = vigenere_encrypt(raw_data, master_key)
    
    entry_result.delete(0, tk.END)
    entry_result.insert(0, password_result)

def decrypt_password():
    cipher_text = entry_result.get()
    master_key = entry_key.get()
    
    if not cipher_text or not master_key:
        messagebox.showerror("Error", "Isi Master Key dan Kotak Hasil Password!")
        return
        
    original_text = vigenere_decrypt(cipher_text, master_key)
    messagebox.showinfo("Hasil Dekripsi", f"Teks Asli (Layanan+User):\n{original_text}")

# --- BAGIAN 3: TAMPILAN (GUI) ---

root = tk.Tk()
root.title("Vigenère Password Manager")
root.geometry("450x400")
root.configure(bg="#f0f0f0")

label_title = tk.Label(root, text="Password Generator", font=("Arial", 16, "bold"), bg="#f0f0f0")
label_title.pack(pady=10)

# Input Service
tk.Label(root, text="Nama Layanan:", bg="#f0f0f0").pack()
entry_service = tk.Entry(root, width=40)
entry_service.pack(pady=2)

# Input Username
tk.Label(root, text="Username:", bg="#f0f0f0").pack()
entry_username = tk.Entry(root, width=40)
entry_username.pack(pady=2)

# Input Master Key
tk.Label(root, text="Master Key:", bg="#f0f0f0").pack()
entry_key = tk.Entry(root, show="*", width=40)
entry_key.pack(pady=2)

# Frame Tombol
frame_buttons = tk.Frame(root, bg="#f0f0f0")
frame_buttons.pack(pady=15)

# Tombol Encrypt
btn_generate = tk.Button(frame_buttons, text="Buat Password", command=generate_password, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
btn_generate.pack(side=tk.LEFT, padx=10)

# Tombol Decrypt
btn_decrypt = tk.Button(frame_buttons, text="Cek Asli", command=decrypt_password, bg="#2196F3", fg="white", font=("Arial", 10, "bold"))
btn_decrypt.pack(side=tk.LEFT, padx=10)

# Output
tk.Label(root, text="Password Hasil:", bg="#f0f0f0").pack()
entry_result = tk.Entry(root, width=40, font=("Courier", 12))
entry_result.pack(pady=5)

root.mainloop()