import tkinter as tk
import encrypttool
from encrypttool import encrypt_file, decrypt_file
import os
from os import remove, system

db_path = [r"data.json"]
log_path = r"seekr.log"

# Create the main application window
root = tk.Tk()
root.title("nyaaa cpp psyop's silly tool")

#Set the geometry of Tkinter frame
root.geometry("600x500")


# Create a label
label = tk.Label(root, text="Password to the SEEKR database file:")
label.pack(pady=10)

def encrypt_usingInput():
    global password  # Declare a global variable to store the input
    password = entry.get()
    for file in db_path:
        encrypttool.encrypt_file(file, password)
        os.remove(file) # if file is encrypted == delete old unencrypted backup. duh
    
    print("ENCRYPTED.")
    print("Securely deleting file: {log_path} ")
    length = os.path.getsize(log_path)
    with open(log_path, "br+", buffering=-1) as f:
        for i in range(passes):
            f.seek(0)
            f.write(os.urandom(length))
        f.close()
    print("{log_path} deletion successful.")

def decrypt_usingInput():
    global password  # Declare a global variable to store the input
    password = entry.get()
    for file in db_path:
        salt_file_path = file + ".salt"
        iv_path = file + ".iv"
        file = file + ".encrypted" # might work

        encrypttool.decrypt_file(salt_file_path,iv_path, file, password) # db_path+.pld because encrypted output is stored as [ORIGINALFILENAME].pld
    return 

entry = tk.Entry(root)
entry.pack()

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_usingInput)
encrypt_button.pack(pady=5)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_usingInput)
decrypt_button.pack(pady=5)

#launch_seekr = tk.Button(root, text="Launch Seekr", command=encrypt_usingInput) # will fix later
#launch_seekr.pack(pady=10)

#kill_seekr = tk.Button(root, text="Exit Seekr", command=encrypt_usingInput) # ^^
#kill_seekr.pack(pady=10)

# Initialize the input variable
input_var = ""

# Start the tkinter main loop
root.mainloop()
