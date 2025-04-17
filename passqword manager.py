import tkinter as tk
from tkinter import simpledialog, messagebox, PhotoImage
from cryptography.fernet import Fernet, InvalidToken
import tkinter.ttk as ttk

root = None

def load_key():
    try:
        file = open("key.key", "rb")
        key = file.read()
        file.close()
        return key
    except FileNotFoundError:
        return None

def save_key(key):
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def generate_key():
    key = Fernet.generate_key()
    save_key(key)
    return key

def open_view_window():
    view_window = tk.Toplevel(root)
    view_window.title("View Passwords")
    view_window.geometry(f"{view_window.winfo_screenwidth()}x{view_window.winfo_screenheight()}")

    tree = ttk.Treeview(view_window, columns=("User", "Password"), show="headings", height=20)
    tree.heading("#0", text="Index")
    tree.heading("User", text="User")
    tree.heading("Password", text="Password")
 
    style = ttk.Style()
    style.configure("Treeview",
                    bd=1,
                    font=('Helvetica', 12),
                    background="#F6FF33", 
                    foreground="black", 
                    fieldbackground="black",
                    separatorcolor="white",  
                    separatorwidth=5)  

    tree["style"] = "Treeview"

    with open('passwords.txt', 'r') as f:
        index = 1
        for line in f.readlines():
            data = line.rstrip()
            user, passw = data.split("|")
            try:
                decrypted_password = fer.decrypt(passw.encode()).decode()
                tree.insert("", index, values=(user, decrypted_password))
            except InvalidToken:
                tree.insert("", index, values=(user, "InvalidToken"))
            except Exception as e:
                tree.insert("", index, values=(user, f"Error: {str(e)}"))
            index += 1

    tree.pack(expand=True, fill="both")
    
name_entry = None
password_entry = None

def add(account_name, password):
    with open('passwords.txt', 'a') as f:
        f.write(account_name + "|" + fer.encrypt(password.encode()).decode() + "\n")

def add_account():
    global name_entry, password_entry, add_window

    if name_entry is not None and password_entry is not None:
        name = name_entry.get()
        password = password_entry.get()

        if name and password:
            add(name, password)
            messagebox.showinfo("Success", "Password added successfully.")
            add_window.destroy()
        else:
            messagebox.showwarning("Error", "Both Account Name and Password are required.")
    else:
        messagebox.showerror("Error", "Entry widgets not properly initialized.")

def open_add_window():
    global root,name_entry, password_entry, add_window

    add_window = tk.Toplevel(root)
    add_window.title("Add Password")
    add_window.configure(bg="#000000")
    add_window.geometry(f"{add_window.winfo_screenwidth()}x{add_window.winfo_screenheight()}")
    name_label = tk.Label(add_window, text="Account Name:", bg="#FF99CC", font=("Cascadia Code", 12))
    name_entry = tk.Entry(add_window, font=("Cascadia Code", 12))
    password_label = tk.Label(add_window, text="Password:", bg="#FF99CC", font=("Cascadia Code", 12))
    password_entry = tk.Entry(add_window, show="*", font=("Cascadia Code", 12))
    add_button = tk.Button(add_window, text="Add Password", command=add_account, **create_button_style())

    name_label.pack(pady=5)
    name_entry.pack(pady=5)
    password_label.pack(pady=5)
    password_entry.pack(pady=5)
    add_button.pack(pady=10)

def delete(account_name):
    with open('passwords.txt', 'r') as f:
        lines = f.readlines()

    with open('passwords.txt', 'w') as f:
        deleted = False
        for line in lines:
            data = line.rstrip()
            user, _ = data.split("|")
            if user == account_name:
                deleted = True
            else:
                f.write(line)

        if deleted:
            messagebox.showinfo("Success", "Password deleted successfully.")
        else:
            messagebox.showwarning("Error", "Account not found.")

def open_delete_window():
    global root
    delete_window = tk.Toplevel(root)
    delete_window.title("Delete Password")
    delete_window.geometry(f"{delete_window.winfo_screenwidth()}x{delete_window.winfo_screenheight()}")
    delete_window.configure(bg="#000000")
    
    def delete_account():
        account_name = account_name_entry.get()
        if account_name:
            delete(account_name)
            delete_window.destroy()
        else:
            messagebox.showwarning("Error", "Account Name is required.")

    account_name_label = tk.Label(delete_window, text="Account Name:", bg="#FF99CC", font=("Cascadia Code", 12))
    account_name_entry = tk.Entry(delete_window, font=("Cascadia Code", 12))
    delete_button = tk.Button(delete_window, text="Delete Password", command=delete_account, **create_button_style())
    
    account_name_label.pack(pady=5)
    account_name_entry.pack(pady=5)
    delete_button.pack(pady=10)

def update(account_name, new_password):
    with open('passwords.txt', 'r') as f:
        lines = f.readlines()

    with open('passwords.txt', 'w') as f:
        updated = False
        for line in lines:
            data = line.rstrip()
            user, old_pass = data.split("|")
            if user == account_name:
                f.write(user + "|" + fer.encrypt(new_password.encode()).decode() + "\n")
                updated = True
            else:
                f.write(line)

        if updated:
            messagebox.showinfo("Success", "Password updated successfully.")
        else:
            messagebox.showwarning("Error", "Account not found.")

def open_update_window():
    global root
    update_window = tk.Toplevel(root)
    update_window.title("Update Password")
    update_window.geometry(f"{update_window.winfo_screenwidth()}x{update_window.winfo_screenheight()}")
    update_window.configure(bg="#000000")
    
    def update_password():
        account_name = account_name_entry.get()
        new_password = new_password_entry.get()
        if account_name and new_password:
            update(account_name, new_password)
            update_window.destroy()
        else:
            messagebox.showwarning("Error", "Both Account Name and New Password are required.")

    account_name_label = tk.Label(update_window, text="Account Name:", bg="#FF99CC", font=("Cascadia Code", 12))
    account_name_entry = tk.Entry(update_window, font=("Cascadia Code", 12))
    new_password_label = tk.Label(update_window, text="New Password:", bg="#FF99CC", font=("Cascadia Code", 12))
    new_password_entry = tk.Entry(update_window, show="*", font=("Cascadia Code", 12))
    update_button = tk.Button(update_window, text="Update Password", command=update_password, **create_button_style())
    
    account_name_label.pack(pady=5)
    account_name_entry.pack(pady=5)
    new_password_label.pack(pady=5)
    new_password_entry.pack(pady=5)
    update_button.pack(pady=10)

def create_button_style():
    return {
        "width": 20,
        "height": 3,
        "font": ("Forte", 16),
        "bg": "#993366",
        "fg": "white",
        "bd": 5,
    }

key = load_key()
if key is None:
    key = generate_key()

fer = Fernet(key)

def check_master_password():
    entered_password = entry.get()
    if entered_password == "1234":
        master_password_dialog.destroy()

        root = tk.Tk()
        root.title("Password Manager")
        root.geometry(f"{root.winfo_screenwidth()}x{root.winfo_screenheight()}")
        
        image_path=PhotoImage(file=r"C:\Users\aakar\Downloads\best-password-manager111.gif")
        bg_image = tk.Label(root, image=image_path)
        bg_image.place(relheight=1 , relwidth=1)
        
        label = tk.Label(root, text="Password manager", font=("Engravers MT", 30), bg="#333366")
        label.pack(side=tk.TOP, pady=10, anchor=tk.CENTER)
        root.configure(bg="#FFCCFF")

        view_button = tk.Button(root, text="View Passwords", command=open_view_window, **create_button_style())
        view_button.pack(side=tk.TOP, pady=30, anchor=tk.CENTER)

        add_button = tk.Button(root, text="Add Password", command=open_add_window, **create_button_style())
        add_button.pack(side=tk.TOP, pady=30, anchor=tk.CENTER)

        delete_button = tk.Button(root, text="Delete Password", command=open_delete_window, **create_button_style())
        delete_button.pack(side=tk.TOP, pady=30, anchor=tk.CENTER)

        update_button = tk.Button(root, text="Update Password", command=open_update_window, **create_button_style())
        update_button.pack(side=tk.TOP, pady=30, anchor=tk.CENTER)

        root.mainloop()
    else:
        messagebox.showerror("Error", "Incorrect Master Password. Exiting...")
        master_password_dialog.destroy()  # Close the master_password_dialog when the password is incorrect

master_password_dialog = tk.Tk()
master_password_dialog.title("Master Password")
master_password_dialog.geometry(f"{master_password_dialog.winfo_screenwidth()}x{master_password_dialog.winfo_screenheight()}") 
image_path=PhotoImage(file=r"C:\Users\aakar\Downloads\mp.gif")

bg_image = tk.Label(master_password_dialog, image=image_path)
bg_image.place(relheight=1 , relwidth=1)

label = tk.Label(master_password_dialog, text="Enter the Master Password:", font=("Helvetica", 30), bg="#E57373", fg="white")
label.pack(pady=40)

entry = tk.Entry(master_password_dialog, show='*', font=("Helvetica", 35), bg="#FFCDD2")
entry.pack(pady=10)

ok_button = tk.Button(master_password_dialog, text="OK", command=check_master_password, width=20, height=3, bg="#4CAF50", fg="white", font=("Helvetica", 12))
ok_button.pack(pady=10)

master_password_dialog.mainloop()
