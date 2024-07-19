import tkinter as tk
from tkinter import messagebox, ttk
from impacket.smbconnection import SMBConnection

class SMBEnumeratorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SMB Enumerator")
        self.geometry("400x300")
        self.create_widgets()

    def create_widgets(self):
        self.label_ip = tk.Label(self, text="IP do Alvo:")
        self.label_ip.pack(pady=5)
        self.entry_ip = tk.Entry(self)
        self.entry_ip.pack(pady=5)

        self.label_username = tk.Label(self, text="Nome de Usuário:")
        self.label_username.pack(pady=5)
        self.entry_username = tk.Entry(self)
        self.entry_username.pack(pady=5)

        self.label_password = tk.Label(self, text="Senha:")
        self.label_password.pack(pady=5)
        self.entry_password = tk.Entry(self, show='*')
        self.entry_password.pack(pady=5)

        self.button_enumerate = tk.Button(self, text="Enumerar SMB", command=self.enumerate_smb)
        self.button_enumerate.pack(pady=10)

        self.result_frame = ttk.LabelFrame(self, text="Resultados")
        self.result_frame.pack(padx=10, pady=10, fill="both", expand=True)
        self.result_text = tk.Text(self.result_frame)
        self.result_text.pack(padx=5, pady=5, fill="both", expand=True)

    def enumerate_smb(self):
        ip = self.entry_ip.get()
        username = self.entry_username.get()
        password = self.entry_password.get()

        try:
            smb = SMBConnection(ip, ip)
            smb.login(username, password)
            shares = smb.listShares()
            self.result_text.delete(1.0, tk.END)
            for share in shares:
                share_info = f"Share Name: {share['shi1_netname'][:-1]}\nComment: {share['shi1_remark'][:-1]}\n\n"
                self.result_text.insert(tk.END, share_info)
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao enumerar SMB: {e}")

if __name__ == "__main__":
    app = SMBEnumeratorApp()
    app.mainloop()