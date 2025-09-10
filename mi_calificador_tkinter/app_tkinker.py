import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
from bcrypt import hashpw, gensalt, checkpw
from functools import partial
import pandas as pd
import io

DATABASE = 'calificaciones.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    """Crea las tablas de la base de datos si no existen."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash BLOB NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS calificaciones (
            id INTEGER PRIMARY KEY,
            materia TEXT NOT NULL,
            nota REAL NOT NULL,
            peso REAL DEFAULT 1.0,
            nombre_actividad TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

class LoginRegisterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Iniciar Sesión / Registro")
        self.root.geometry("350x250")
        self.current_user_id = None
        self.main_window = None

        self.create_login_widgets()

    def create_login_widgets(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.login_frame = ttk.Frame(self.root, padding="20")
        self.login_frame.pack(expand=True)

        ttk.Label(self.login_frame, text="Usuario:", font=('Helvetica', 12)).grid(row=0, column=0, pady=5)
        self.username_entry = ttk.Entry(self.login_frame, width=25)
        self.username_entry.grid(row=0, column=1, pady=5)

        ttk.Label(self.login_frame, text="Contraseña:", font=('Helvetica', 12)).grid(row=1, column=0, pady=5)
        self.password_entry = ttk.Entry(self.login_frame, show="*", width=25)
        self.password_entry.grid(row=1, column=1, pady=5)

        ttk.Button(self.login_frame, text="Iniciar Sesión", command=self.check_login).grid(row=2, column=0, pady=15, padx=5)
        ttk.Button(self.login_frame, text="Registrarse", command=self.show_register_widgets).grid(row=2, column=1, pady=15, padx=5)

    def show_register_widgets(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.register_frame = ttk.Frame(self.root, padding="20")
        self.register_frame.pack(expand=True)

        ttk.Label(self.register_frame, text="Usuario:", font=('Helvetica', 12)).grid(row=0, column=0, pady=5)
        self.reg_username_entry = ttk.Entry(self.register_frame, width=25)
        self.reg_username_entry.grid(row=0, column=1, pady=5)

        ttk.Label(self.register_frame, text="Contraseña:", font=('Helvetica', 12)).grid(row=1, column=0, pady=5)
        self.reg_password_entry = ttk.Entry(self.register_frame, show="*", width=25)
        self.reg_password_entry.grid(row=1, column=1, pady=5)
        
        ttk.Button(self.register_frame, text="Registrar", command=self.register_user).grid(row=2, column=0, pady=15, padx=5)
        ttk.Button(self.register_frame, text="Cancelar", command=self.create_login_widgets).grid(row=2, column=1, pady=15, padx=5)

    def register_user(self):
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get().encode('utf-8')
        
        if not all([username, password]):
            messagebox.showerror("Error", "Todos los campos son obligatorios.")
            return

        hashed_password = hashpw(password, gensalt())

        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            messagebox.showinfo("Registro Exitoso", "Usuario registrado con éxito.")
            self.create_login_widgets()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "El nombre de usuario ya existe.")
        finally:
            conn.close()

    def check_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get().encode('utf-8')

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and checkpw(password, user['password_hash']):
            self.current_user_id = user['id']
            self.main_window = MainApp(tk.Toplevel(self.root), self.current_user_id)
            self.root.withdraw()
        else:
            messagebox.showerror("Error", "Usuario o contraseña inválidos.")

class MainApp:
    def __init__(self, root, user_id):
        self.root = root
        self.user_id = user_id
        self.root.title("Gestor de Calificaciones")
        self.root.geometry("800x600")

        self.create_widgets()
        self.load_calificaciones()
        self.calculate_promedios()

    def create_widgets(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Frame para añadir calificación
        add_frame = ttk.Frame(self.root, padding="10")
        add_frame.pack(fill=tk.X)
        
        ttk.Label(add_frame, text="Materia:").pack(side=tk.LEFT, padx=5)
        self.materia_entry = ttk.Entry(add_frame, width=15)
        self.materia_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(add_frame, text="Actividad:").pack(side=tk.LEFT, padx=5)
        self.actividad_entry = ttk.Entry(add_frame, width=15)
        self.actividad_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(add_frame, text="Nota:").pack(side=tk.LEFT, padx=5)
        self.nota_entry = ttk.Entry(add_frame, width=8)
        self.nota_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(add_frame, text="Peso:").pack(side=tk.LEFT, padx=5)
        self.peso_entry = ttk.Entry(add_frame, width=8)
        self.peso_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(add_frame, text="Añadir", command=self.add_calificacion).pack(side=tk.LEFT, padx=5)
        ttk.Button(add_frame, text="Importar Excel", command=self.import_calificaciones).pack(side=tk.LEFT, padx=5)
        ttk.Button(add_frame, text="Exportar a Excel", command=self.export_calificaciones).pack(side=tk.LEFT, padx=5)

        # Frame para promedios
        promedios_frame = ttk.Frame(self.root, padding="10")
        promedios_frame.pack(fill=tk.X)
        self.promedio_label = ttk.Label(promedios_frame, text="Promedio General: ", font=('Helvetica', 14, 'bold'))
        self.promedio_label.pack(side=tk.LEFT, padx=10)
        
        self.promedios_tree = ttk.Treeview(promedios_frame, columns=("materia", "promedio"), show="headings", height=5)
        self.promedios_tree.heading("materia", text="Materia")
        self.promedios_tree.heading("promedio", text="Promedio")
        self.promedios_tree.pack(fill=tk.X, pady=5)
        
        # Tabla de calificaciones
        table_frame = ttk.Frame(self.root, padding="10")
        table_frame.pack(fill=tk.BOTH, expand=True)

        self.table = ttk.Treeview(table_frame, columns=("materia", "actividad", "nota", "peso", "id"), show="headings")
        self.table.heading("materia", text="Materia")
        self.table.heading("actividad", text="Actividad")
        self.table.heading("nota", text="Nota")
        self.table.heading("peso", text="Peso")
        self.table.column("id", width=0, stretch=tk.NO)
        self.table.pack(fill=tk.BOTH, expand=True)
        
        # Botones de acción
        action_frame = ttk.Frame(self.root, padding="10")
        action_frame.pack(fill=tk.X)
        ttk.Button(action_frame, text="Editar", command=self.edit_calificacion).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Eliminar", command=self.delete_calificacion).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Cerrar Sesión", command=self.logout).pack(side=tk.RIGHT, padx=5)

    def load_calificaciones(self):
        for row in self.table.get_children():
            self.table.delete(row)

        conn = get_db_connection()
        calificaciones = conn.execute('SELECT * FROM calificaciones WHERE user_id = ?', (self.user_id,)).fetchall()
        conn.close()

        for calificacion in calificaciones:
            self.table.insert('', tk.END, values=(calificacion['materia'], calificacion['nombre_actividad'], calificacion['nota'], calificacion['peso'], calificacion['id']))

    def calculate_promedios(self):
        for row in self.promedios_tree.get_children():
            self.promedios_tree.delete(row)
        
        conn = get_db_connection()
        materias = conn.execute('SELECT DISTINCT materia FROM calificaciones WHERE user_id = ?', (self.user_id,)).fetchall()
        
        total_promedio = 0
        total_peso = 0
        
        for materia in materias:
            calificaciones = conn.execute('SELECT nota, peso FROM calificaciones WHERE materia = ? AND user_id = ?', (materia['materia'], self.user_id)).fetchall()
            
            promedio_materia = 0
            peso_materia = 0
            
            for cal in calificaciones:
                promedio_materia += cal['nota'] * cal['peso']
                peso_materia += cal['peso']
                
            if peso_materia > 0:
                promedio_final_materia = promedio_materia / peso_materia
                self.promedios_tree.insert('', tk.END, values=(materia['materia'], f"{promedio_final_materia:.2f}"))
                total_promedio += promedio_materia
                total_peso += peso_materia

        if total_peso > 0:
            promedio_general = total_promedio / total_peso
            self.promedio_label.config(text=f"Promedio General: {promedio_general:.2f}")
        else:
            self.promedio_label.config(text="Promedio General: N/A")
        
        conn.close()

    def add_calificacion(self):
        materia = self.materia_entry.get()
        actividad = self.actividad_entry.get()
        nota = self.nota_entry.get()
        peso = self.peso_entry.get()

        if not all([materia, actividad, nota, peso]):
            messagebox.showerror("Error", "Todos los campos son obligatorios.")
            return

        try:
            nota = float(nota)
            peso = float(peso)
        except ValueError:
            messagebox.showerror("Error", "La nota y el peso deben ser números válidos.")
            return

        conn = get_db_connection()
        conn.execute('INSERT INTO calificaciones (materia, nota, peso, nombre_actividad, user_id) VALUES (?, ?, ?, ?, ?)', (materia, nota, peso, actividad, self.user_id))
        conn.commit()
        conn.close()
        
        self.materia_entry.delete(0, tk.END)
        self.actividad_entry.delete(0, tk.END)
        self.nota_entry.delete(0, tk.END)
        self.peso_entry.delete(0, tk.END)
        
        self.load_calificaciones()
        self.calculate_promedios()
        
    def edit_calificacion(self):
        selected_item = self.table.focus()
        if not selected_item:
            messagebox.showerror("Error", "Seleccione una calificación para editar.")
            return
        
        item_values = self.table.item(selected_item)['values']
        calificacion_id = item_values[4]
        
        edit_window = tk.Toplevel(self.root)
        edit_window.title("Editar Calificación")

        conn = get_db_connection()
        calificacion = conn.execute('SELECT * FROM calificaciones WHERE id = ?', (calificacion_id,)).fetchone()
        conn.close()
        
        ttk.Label(edit_window, text="Materia:").grid(row=0, column=0, padx=5, pady=5)
        materia_entry = ttk.Entry(edit_window)
        materia_entry.insert(0, calificacion['materia'])
        materia_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(edit_window, text="Actividad:").grid(row=1, column=0, padx=5, pady=5)
        actividad_entry = ttk.Entry(edit_window)
        actividad_entry.insert(0, calificacion['nombre_actividad'])
        actividad_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(edit_window, text="Nota:").grid(row=2, column=0, padx=5, pady=5)
        nota_entry = ttk.Entry(edit_window)
        nota_entry.insert(0, calificacion['nota'])
        nota_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(edit_window, text="Peso:").grid(row=3, column=0, padx=5, pady=5)
        peso_entry = ttk.Entry(edit_window)
        peso_entry.insert(0, calificacion['peso'])
        peso_entry.grid(row=3, column=1, padx=5, pady=5)
        
        def save_edit():
            materia = materia_entry.get()
            actividad = actividad_entry.get()
            nota = nota_entry.get()
            peso = peso_entry.get()
            
            try:
                nota_f = float(nota)
                peso_f = float(peso)
            except ValueError:
                messagebox.showerror("Error", "La nota y el peso deben ser números válidos.", parent=edit_window)
                return

            conn = get_db_connection()
            conn.execute('UPDATE calificaciones SET materia = ?, nombre_actividad = ?, nota = ?, peso = ? WHERE id = ?', (materia, actividad, nota_f, peso_f, calificacion_id))
            conn.commit()
            conn.close()
            
            self.load_calificaciones()
            self.calculate_promedios()
            edit_window.destroy()

        ttk.Button(edit_window, text="Guardar Cambios", command=save_edit).grid(row=4, column=0, columnspan=2, pady=10)

    def delete_calificacion(self):
        selected_item = self.table.focus()
        if not selected_item:
            messagebox.showerror("Error", "Seleccione una calificación para eliminar.")
            return

        confirm = messagebox.askyesno("Confirmación", "¿Está seguro de que desea eliminar esta calificación?")
        if confirm:
            calificacion_id = self.table.item(selected_item)['values'][4]
            conn = get_db_connection()
            conn.execute('DELETE FROM calificaciones WHERE id = ?', (calificacion_id,))
            conn.commit()
            conn.close()
            
            self.load_calificaciones()
            self.calculate_promedios()

    def logout(self):
        self.root.master.deiconify()
        self.root.destroy()
        
    def on_closing(self):
        self.root.master.deiconify()
        self.root.destroy()

    def import_calificaciones(self):
        file_path = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx")])
        if not file_path:
            return

        try:
            df = pd.read_excel(file_path)
            conn = get_db_connection()
            for index, row in df.iterrows():
                conn.execute('INSERT INTO calificaciones (materia, nota, peso, nombre_actividad, user_id) VALUES (?, ?, ?, ?, ?)', 
                             (row['materia'], row['nota'], row['peso'], row['nombre_actividad'], self.user_id))
            conn.commit()
            conn.close()
            messagebox.showinfo("Importación Exitosa", "Calificaciones importadas con éxito.")
            self.load_calificaciones()
            self.calculate_promedios()
        except Exception as e:
            messagebox.showerror("Error de Importación", f"Hubo un error al importar el archivo: {e}")

    def export_calificaciones(self):
        try:
            conn = get_db_connection()
            df = pd.read_sql_query('SELECT materia, nombre_actividad, nota, peso FROM calificaciones WHERE user_id = ?', conn, params=(self.user_id,))
            conn.close()
            
            file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")], initialfile="Calificaciones")
            if file_path:
                df.to_excel(file_path, index=False, sheet_name='Calificaciones')
                messagebox.showinfo("Exportación Exitosa", f"Calificaciones exportadas a:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error de Exportación", f"Hubo un error al exportar el archivo: {e}")

if __name__ == "__main__":
    create_tables()
    root = tk.Tk()
    app = LoginRegisterApp(root)
    root.mainloop() 