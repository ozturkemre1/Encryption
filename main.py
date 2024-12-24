from tkinter import *
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def save_and_encrypt_notes():
    title = title_entry.get()
    message = secret_textbox.get("1.0", END)
    master = master_entry.get()

    if len(title) == 0 or len(message) == 0 or len(master) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info.")
    else:
        #encryption
        message_encrypted = encode(master,message)
        try:
            with open("mySecret.txt","a",encoding="utf-8") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mySecret.txt", "w", encoding="utf-8") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            title_entry.delete(0,END)
            secret_textbox.delete("1.0",END)
            master_entry.delete(0,END)

def decrypt_notes():
    message_encrypted = secret_textbox.get("1.0",END)
    master = master_entry.get()

    if len(message_encrypted) == 0 or len(master) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info.")
    else:
        try:
            decrypted_message = decode(master,message_encrypted)
            secret_textbox.delete("1.0",END)
            secret_textbox.insert("1.0",decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please enter encrypted text!")

#UI
window = Tk()
window.title("Secret Notes")
window.minsize(width=500,height=800)

#image
image = PhotoImage(file="top-secret.png")
resized_image = image.subsample(8) #8 kat küçültür
image_label = Label(window, image=resized_image)
image_label.pack(pady=(30,0))

#title
title_label = Label(text="Enter your title",font=('Arial',15,"bold"))
title_label.pack(pady=(15,0))
title_entry = Entry(
    width=50,
    fg="#333333",
    highlightthickness=2  # Kenarlık kalınlığı
)
title_entry.pack(pady=(5,0))

#secret
secret_label = Label(text="Enter your secret",font=('Arial',15,"bold"))
secret_label.pack(pady=(15,0))
secret_textbox= Text(
    width=50,
    height=15,
    fg="#333333",
    highlightthickness=2  # Kenarlık kalınlığı
)
secret_textbox.pack(pady=(5,0))

#master
master_label = Label(text="Enter master key",font=('Arial',15,"bold"))
master_label.pack(pady=(15,0))
master_entry = Entry(
    width=50,
    fg="#333333",
    highlightthickness=2  # Kenarlık kalınlığı
)
master_entry.pack(pady=(5,0))

#save & encrypt
save_button = Button(
    text="Save & Encrypt",command=save_and_encrypt_notes,
    font=("Arial", 10, "bold"),
    bg="#4CAF50",
    fg="white",
    padx=10,
    pady=5)
save_button.pack(pady=(10,0))

#decrypt
decrypt_button = Button(
    text="Decrypt",
    command=decrypt_notes,
    font=("Arial", 10, "bold"),
    bg="#2196F3",
    fg="white",
    padx=10,
    pady=5
)
decrypt_button.pack(pady=(10,0))



window.mainloop()