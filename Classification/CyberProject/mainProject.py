import tkinter as tk
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from joblib import load
import numpy as np
import random as rand
import pandas as pd

dos = probe = r2l = u2r = normal = 0

def feedData():
    global dos, probe, r2l, u2r, normal
    dos = probe = r2l = u2r = normal = 0
    model = load('model_new.joblib')
    num = rand.randint(1, 41)

    df = pd.read_csv(f'trafficTestSet/testSet_{num}.csv')

    pred = model.predict(df)
    pred = np.argmax(pred, axis=1)

    for i in pred:
        if i==0:
            dos += 1
        elif i==1:
            probe += 1
        elif i==2:
            r2l += 1
        elif i==3:
            u2r += 1
        else:
            normal += 1

    df['flag'] = df.iloc[:, 1:12].apply(lambda row: ', '.join(col for col, val in row.items() if val), axis=1)

    columns_to_integrate = ['aol', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain', 'domain_u', 
                        'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data', 'gopher', 'harvest', 
                        'hostnames', 'http', 'http_2784', 'http_443', 'http_8001', 'imap4', 'IRC', 'iso_tsap', 'klogin', 
                        'kshell', 'ldap', 'link', 'login', 'mtp', 'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 
                        'netstat', 'nnsp', 'nntp', 'ntp_u', 'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 
                        'red_i', 'remote_job', 'rje', 'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup', 'systat', 
                        'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i', 'urp_i', 'uucp', 'uucp_path', 'vmnet', 'whois', 'X11', 'Z39_50']
    df['service'] = df[columns_to_integrate].apply(lambda row: ', '.join(col for col, val in row.items() if val), axis=1)

    columns_to_integrate = ['tcp','udp', 'icmp']
    df['protocol_type'] = df[columns_to_integrate].apply(lambda row: ', '.join(col for col, val in row.items() if val), axis=1)

    df = df.drop(['OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0', 'S1', 'S2', 'S3', 'SF', 'SH',
            'aol', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain', 'domain_u', 
            'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data', 'gopher', 'harvest', 
            'hostnames', 'http', 'http_2784', 'http_443', 'http_8001', 'imap4', 'IRC', 'iso_tsap', 'klogin', 
            'kshell', 'ldap', 'link', 'login', 'mtp', 'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 
            'netstat', 'nnsp', 'nntp', 'ntp_u', 'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 
            'red_i', 'remote_job', 'rje', 'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup', 'systat', 
            'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i', 'urp_i', 'uucp', 'uucp_path', 'vmnet', 'whois', 'X11', 'Z39_50',
            'tcp','udp', 'icmp'], axis=1)

    df['predict'] = pred.tolist()

    return df

def preChart():
    data = feedData()
    df = pd.DataFrame({
        "Type": ['DoS', 'Probe', 'R2L', 'U2R'],
        "Value": [dos, probe, r2l, u2r]
    })
    return df, data

class IDS_Dashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System")
        self.root.geometry("900x600")
        self.root.configure(bg="white")
        self.root.protocol("WM_DELETE_WINDOW", self.exit_program)

        self.df = pd.DataFrame({"Type": ['DoS', 'Probe', 'R2L', 'U2R'], "Value": [dos, probe, r2l, u2r]})
        base_columns = ['flag', 'service', 'protocol_type', 'predict']
        base_col = ['a', 'b', 'c', 'd']
        columns = [f"{col}_{i+1}" for i in range(27) for col in base_col]
        column = base_columns + columns
        self.data = pd.DataFrame(columns=column)

        self.create_header()
        self.create_summary()
        self.create_pie_chart()
        self.create_table()

    def create_header(self):
        header_frame = tk.Frame(self.root, bg="#2E86C1")
        header_frame.pack(fill="x")

        title_label = tk.Label(
            header_frame,
            text="Intrusion Detection System",
            font=("Arial", 20, "bold"),
            bg="#2E86C1",
            fg="white",
            anchor="w"
        )
        title_label.pack(side="left", padx=20, pady=10, fill="x", expand=True)

        button_frame = tk.Frame(header_frame, bg="#2E86C1")
        button_frame.pack(side="right", padx=20)

        start_button = tk.Button(
            button_frame,
            text="START",
            command=self.start_system,
            font=("Arial", 12),
            bg="green",
            fg="white",
            relief="raised",
            width=8
        )
        start_button.pack(side="left", padx=10)

        exit_button = tk.Button(
            button_frame,
            text="EXIT",
            command=self.exit_program,
            font=("Arial", 12),
            bg="red",
            fg="white",
            relief="raised",
            width=8
        )
        exit_button.pack(side="left")

    def create_summary(self):
        summary_frame = tk.Frame(self.root, bg="white")
        summary_frame.pack(pady=20)
        self.all_traffic_label = tk.Label(
            summary_frame,
            text="All Traffic\n0",
            font=("Arial", 16),
            width=15,
            height=3,
            relief="groove",
            bg="#D6EAF8"
        )
        self.all_traffic_label.grid(row=0, column=0, padx=10)

        self.normal_traffic_label = tk.Label(
            summary_frame,
            text="Normal\n0",
            font=("Arial", 16),
            width=15,
            height=3,
            relief="groove",
            bg="#D5F5E3"
        )
        self.normal_traffic_label.grid(row=0, column=1, padx=10)

        self.risk_traffic_label = tk.Label(
            summary_frame,
            text="Risk\n0",
            font=("Arial", 16),
            width=15,
            height=3,
            relief="groove",
            bg="#FADBD8"
        )
        self.risk_traffic_label.grid(row=0, column=2, padx=10)

    def create_pie_chart(self):
        self.chart_frame = tk.Frame(self.root, bg="white")
        self.chart_frame.pack(pady=10)
        self.update_pie_chart()

    def create_table(self):
        self.table_frame = tk.Frame(self.root, bg="white")
        self.table_frame.pack(pady=10, fill="both", expand=True)
        columns = ("Index", "Flag", "Service", "Protocol", "Risk")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings", height=8)

        style = ttk.Style()
        style.configure("Treeview.Heading", font=("Arial", 14))
        style.configure("Treeview", font=("Arial", 12))

        self.tree.heading("Index", text="Index")
        self.tree.heading("Flag", text="Flag")
        self.tree.heading("Service", text="Service")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Risk", text="Risk")

        self.v_scrollbar = tk.Scrollbar(self.table_frame, orient="vertical", command=self.tree.yview)
        self.tree.config(yscrollcommand=self.v_scrollbar.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        self.v_scrollbar.grid(row=0, column=1, sticky="ns")

        self.table_frame.grid_rowconfigure(0, weight=1)
        self.table_frame.grid_columnconfigure(0, weight=1)

        self.update_table()

    def update_pie_chart(self):
        for widget in self.chart_frame.winfo_children():
            widget.destroy()

        fig, ax = plt.subplots(figsize=(4, 4))
        data = self.df[self.df["Value"] > 0]
        if not data.empty:
            ax.pie(data["Value"], labels=data["Type"], autopct="%1.1f%%", startangle=140)
            ax.set_title("Risk Chart")
        else:
            ax.text(0.5, 0.5, "No Data", horizontalalignment='center', verticalalignment='center', fontsize=14)
            ax.axis("off")

        chart_canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        chart_canvas.draw()
        chart_canvas.get_tk_widget().pack()

    def update_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        for i, row in self.data.iterrows():
            predict_text = {0: "Dos", 1: "Probe", 2: "R2L", 3: "U2R"}.get(row["predict"], "Normal")
            self.tree.insert("", "end", values=(i + 1, row["flag"], row["service"], row["protocol_type"], predict_text))

    def update_summary(self):
        all_traffic = normal+dos+probe+r2l+u2r
        risk_traffic = dos+probe+r2l+u2r
        normal_traffic = normal

        self.all_traffic_label.config(text=f"All Traffic\n{all_traffic}")
        self.normal_traffic_label.config(text=f"Normal\n{normal_traffic}")
        self.risk_traffic_label.config(text=f"Risk\n{risk_traffic}")

    def start_system(self):
        self.df, self.data = preChart()
        self.update_dashboard()

    def update_dashboard(self):
        self.update_pie_chart()
        self.update_table()
        self.update_summary()

    def exit_program(self):
        self.root.quit()
        self.root.destroy()
        plt.close("all")

if __name__ == "__main__":
    root = tk.Tk()
    dashboard = IDS_Dashboard(root)
    root.mainloop()