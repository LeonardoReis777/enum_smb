#####################################
# Hacking Alchemy                   #
# https://linktr.ee/hackingalchemy  #
#####################################

import tkinter as tk
from tkinter import messagebox, ttk
from impacket.smbconnection import SMBConnection

class SMBEnumeratorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(" |SMB_ENUM_IMPACKET Alchemy|")
        self.geometry("900x700")
        self.configure(bg="#111111")
        self.create_widgets()

    def create_widgets(self):
        # Header
        header = tk.Label(
            self, text="SMB Enumerator", font=("Courier New", 20, "bold"), fg="#33FF00", bg="#111111"
        )
        header.pack(pady=10)

        # IP Input
        self.label_ip = tk.Label(
            self, text="IP do Alvo:", font=("Courier New", 14), fg="#33FF00", bg="#111111"
        )
        self.label_ip.pack(pady=5)
        self.entry_ip = tk.Entry(
            self, font=("Courier New", 14), width=40, relief="flat", bg="#222222", fg="#FFFFFF"
        )
        self.entry_ip.pack(pady=5)

        # Username Input
        self.label_username = tk.Label(
            self, text="Nome de Usuário:", font=("Courier New", 14), fg="#33FF00", bg="#111111"
        )
        self.label_username.pack(pady=5)
        self.entry_username = tk.Entry(
            self, font=("Courier New", 14), width=40, relief="flat", bg="#222222", fg="#FFFFFF"
        )
        self.entry_username.pack(pady=5)

        # Password Input
        self.label_password = tk.Label(
            self, text="Senha:", font=("Courier New", 14), fg="#33FF00", bg="#111111"
        )
        self.label_password.pack(pady=5)
        self.entry_password = tk.Entry(
            self, font=("Courier New", 14), width=40, relief="flat", bg="#222222", fg="#FFFFFF", show="*"
        )
        self.entry_password.pack(pady=5)

        # Enumerate Button
        self.button_enumerate = tk.Button(
            self,
            text="Enumerar SMB",
            font=("Courier New", 14, "bold"),
            bg="#33FF00",
            fg="#000000",
            relief="flat",
            command=self.enumerate_smb,
        )
        self.button_enumerate.pack(pady=10)

        # Results Frame
        self.result_frame = ttk.LabelFrame(self, text="Resultados", style="TFrame")
        self.result_frame.pack(padx=20, pady=10, fill="both", expand=True)
        self.result_text = tk.Text(
            self.result_frame, font=("Courier New", 12), bg="#222222", fg="#33FF00", wrap="word"
        )
        self.result_text.pack(padx=10, pady=10, fill="both", expand=True)

        # Footer
        footer = tk.Label(
            self,
            text="Desenvolvido por Hacking Alchemy",
            font=("Courier New", 10),
            fg="#888888",
            bg="#111111",
        )
        footer.pack(pady=10)

    def enumerate_smb(self):
        ip = self.entry_ip.get()
        username = self.entry_username.get()
        password = self.entry_password.get()

        self.result_text.delete(1.0, tk.END)  # Clear previous results
        try:
            smb = SMBConnection(ip, ip)
            smb.login(username, password)
            shares = smb.listShares()
            if shares:
                for share in shares:
                    share_info = f"Share Name: {share['shi1_netname'][:-1]}\nComment: {share['shi1_remark'][:-1]}\n\n"
                    self.result_text.insert(tk.END, share_info)
            else:
                self.result_text.insert(tk.END, "Nenhuma pasta compartilhada encontrada.")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao enumerar SMB: {e}")


if __name__ == "__main__":
    app = SMBEnumeratorApp()
    app.mainloop()
