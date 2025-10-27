import os
import json
import uuid
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Callable, Any

import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinter import ttk

# =============================
# =========== UI THEME ========
# =============================

# Paleta moderna inspirada en el diseño
BG = "#0A0E27"  # Fondo oscuro principal
CARD_BG = "#1A1F3A"  # Tarjetas con tono azul oscuro
CARD_BG_LIGHT = "#242B4A"  # Variante más clara
PRIMARY = "#6366F1"  # Indigo moderno
PRIMARY_HOVER = "#4F46E5"
ACCENT = "#8B5CF6"  # Púrpura para acentos
TEXT = "#F9FAFB"  # Texto claro
MUTED = "#9CA3AF"  # Texto secundario
ERROR_FG = "#EF4444"
SUCCESS_FG = "#10B981"
BORDER = "#374151"

TITLE_FONT = ("Segoe UI", 24, "bold")
SUBTITLE_FONT = ("Segoe UI", 12)
LABEL_FONT = ("Segoe UI", 10)
INPUT_FONT = ("Segoe UI", 11)
BUTTON_FONT = ("Segoe UI", 11, "bold")

DATA_DIR = os.path.join(".", "data")
USERS_JSON = os.path.join(DATA_DIR, "users.json")
ROLES_JSON = os.path.join(DATA_DIR, "roles.json")
AUDIT_LOG = os.path.join(DATA_DIR, "audit_log.jsonl")

os.makedirs(DATA_DIR, exist_ok=True)

# =============================
# ======= ETAPA 1 (LEGACY) ====
# =============================

class Rol:
    def __init__(self, nombre, permisos: List[str]):
        self.nombre = nombre
        self.permisos = permisos

    def tienePermiso(self, accion):
        return accion in self.permisos

class Usuario:
    def __init__(self, nombreUsuario, clave, rol: Rol):
        self.__nombreUsuario = nombreUsuario
        self.__clave = clave
        self.__rol = rol

    def getNombreUsuario(self):
        return self.__nombreUsuario

    def getRol(self):
        return self.__rol

    def validarClave(self, entradaClave):
        return self.__clave == entradaClave

# =============================
# ======= ETAPA 2 (RBAC) ======
# =============================

class Permiso:
    USUARIOS_VER = "USUARIOS.VER"
    USUARIOS_CREAR = "USUARIOS.CREAR"
    USUARIOS_EDITAR = "USUARIOS.EDITAR"
    USUARIOS_BLOQUEAR = "USUARIOS.BLOQUEAR"
    ROLES_VER = "ROLES.VER"
    ROLES_EDITAR = "ROLES.EDITAR"
    PERMISOS_EDITAR = "PERMISOS.EDITAR"
    AUDITORIA_VER = "AUDITORIA.VER"
    CUENTAS_CAMBIAR_CLAVE = "CUENTAS.CAMBIAR_CLAVE"
    SESION_CERRAR = "SESION.CERRAR"

    @staticmethod
    def base_catalog() -> List[str]:
        return [
            Permiso.USUARIOS_VER, Permiso.USUARIOS_CREAR, Permiso.USUARIOS_EDITAR, Permiso.USUARIOS_BLOQUEAR,
            Permiso.ROLES_VER, Permiso.ROLES_EDITAR, Permiso.PERMISOS_EDITAR,
            Permiso.AUDITORIA_VER, Permiso.CUENTAS_CAMBIAR_CLAVE, Permiso.SESION_CERRAR
        ]

class TokenSesion:
    def __init__(self, token: str, user_id: str, expira_en: datetime):
        self.token = token
        self.user_id = user_id
        self.expira_en = expira_en

    def valido(self) -> bool:
        return datetime.utcnow() < self.expira_en

class EventoAuditoria:
    def __init__(self, timestamp: datetime, usuario: str, accion: str, resultado: str, detalle: Optional[dict] = None):
        self.timestamp = timestamp
        self.usuario = usuario
        self.accion = accion
        self.resultado = resultado
        self.detalle = detalle or {}

    def to_json(self):
        return {
            "timestamp": self.timestamp.isoformat(timespec="seconds"),
            "usuario": self.usuario,
            "accion": self.accion,
            "resultado": self.resultado,
            "detalle": self.detalle
        }

class IHasher:
    def hash(self, password: str, salt: Optional[bytes] = None) -> Dict[str, str]:
        raise NotImplementedError

    def verify(self, password: str, hashed: str, salt_hex: str) -> bool:
        raise NotImplementedError

class PBKDF2Hasher(IHasher):
    def hash(self, password: str, salt: Optional[bytes] = None) -> Dict[str, str]:
        if salt is None:
            salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 150_000)
        return {"hash": dk.hex(), "salt": salt.hex()}

    def verify(self, password: str, hashed: str, salt_hex: str) -> bool:
        salt = bytes.fromhex(salt_hex)
        test = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 150_000).hex()
        return hmac.compare_digest(test, hashed)

class ITokenService:
    def emitir(self, user_id: str, ttl_minutes: int = 30) -> TokenSesion:
        raise NotImplementedError

    def validar(self, token: str) -> bool:
        raise NotImplementedError

    def usuario_de(self, token: str) -> Optional[str]:
        raise NotImplementedError

    def invalidar(self, token: str) -> None:
        raise NotImplementedError

class SimpleTokenService(ITokenService):
    def __init__(self):
        self._tokens: Dict[str, TokenSesion] = {}

    def emitir(self, user_id: str, ttl_minutes: int = 30) -> TokenSesion:
        t = uuid.uuid4().hex
        tk = TokenSesion(t, user_id, datetime.utcnow() + timedelta(minutes=ttl_minutes))
        self._tokens[t] = tk
        return tk

    def validar(self, token: str) -> bool:
        tk = self._tokens.get(token)
        return tk is not None and tk.valido()

    def usuario_de(self, token: str) -> Optional[str]:
        tk = self._tokens.get(token)
        if tk and tk.valido():
            return tk.user_id
        return None

    def invalidar(self, token: str) -> None:
        self._tokens.pop(token, None)

class JsonStore:
    def __init__(self, path: str, default_data):
        self.path = path
        self.default_data = default_data
        if not os.path.exists(self.path):
            self._write(default_data)

    def _read(self):
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _write(self, data):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

class UsuariosRepo:
    def __init__(self, store: JsonStore):
        self.store = store

    def all(self) -> List[dict]:
        return self.store._read().get("usuarios", [])

    def save_all(self, usuarios: List[dict]):
        data = {"usuarios": usuarios}
        self.store._write(data)

    def find_by_username(self, username: str) -> Optional[dict]:
        for u in self.all():
            if u["username"] == username:
                return u
        return None

    def find_by_id(self, user_id: str) -> Optional[dict]:
        for u in self.all():
            if u["id"] == user_id:
                return u
        return None

    def upsert(self, user: dict):
        usuarios = self.all()
        for i, u in enumerate(usuarios):
            if u["id"] == user["id"]:
                usuarios[i] = user
                self.save_all(usuarios)
                return
        usuarios.append(user)
        self.save_all(usuarios)

class RolesRepo:
    def __init__(self, store: JsonStore):
        self.store = store

    def all(self) -> List[dict]:
        return self.store._read().get("roles", [])

    def save_all(self, roles: List[dict]):
        self.store._write({"roles": roles})

    def find_by_nombre(self, nombre: str) -> Optional[dict]:
        for r in self.all():
            if r["nombre"] == nombre:
                return r
        return None

    def find_by_id(self, rid: str) -> Optional[dict]:
        for r in self.all():
            if r["id"] == rid:
                return r
        return None

    def upsert(self, rol: dict):
        roles = self.all()
        for i, r in enumerate(roles):
            if r["id"] == rol["id"]:
                roles[i] = rol
                self.save_all(roles)
                return
        roles.append(rol)
        self.save_all(roles)

class EventBus:
    def __init__(self):
        self._subs: Dict[str, List[Callable[[dict], None]]] = {}

    def subscribe(self, topic: str, fn: Callable[[dict], None]):
        self._subs.setdefault(topic, []).append(fn)

    def publish(self, topic: str, payload: dict):
        for fn in self._subs.get(topic, []):
            try:
                fn(payload)
            except Exception:
                pass

class AuditService:
    def __init__(self, eventbus: EventBus):
        self.eventbus = eventbus
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        self.eventbus.subscribe("login_ok", self._on_login_ok)
        self.eventbus.subscribe("login_fail", self._on_login_fail)
        self.eventbus.subscribe("permiso_denegado", self._on_permiso_denegado)
        self.eventbus.subscribe("accion", self._on_accion)

    def _append(self, evt: EventoAuditoria):
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(evt.to_json(), ensure_ascii=False) + "\n")

    def _on_login_ok(self, payload):
        self._append(EventoAuditoria(datetime.utcnow(), payload["usuario"], "LOGIN", "OK"))

    def _on_login_fail(self, payload):
        self._append(EventoAuditoria(datetime.utcnow(), payload["usuario"], "LOGIN", "FAIL", {"motivo": payload.get("motivo","")}))

    def _on_permiso_denegado(self, payload):
        self._append(EventoAuditoria(datetime.utcnow(), payload["usuario"], "PERMISO_DENEGADO", "FAIL", {"permiso": payload.get("permiso","")}))

    def _on_accion(self, payload):
        self._append(EventoAuditoria(datetime.utcnow(), payload.get("usuario","-"), payload.get("accion","ACCION"), payload.get("resultado","OK"), payload.get("detalle",{})))

    def listar_eventos(self) -> List[dict]:
        if not os.path.exists(AUDIT_LOG):
            return []
        out = []
        with open(AUDIT_LOG, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

class RBACService:
    def __init__(self, usuarios: UsuariosRepo, roles: RolesRepo):
        self.usuarios = usuarios
        self.roles = roles

    def _permisos_de_roles(self, role_ids: List[str]) -> set:
        permisos = set()
        for rid in role_ids:
            r = self.roles.find_by_id(rid)
            if r:
                permisos.update(r.get("permisos", []))
        return permisos

    def has_perm(self, user_id: str, permiso: str) -> bool:
        u = self.usuarios.find_by_id(user_id)
        if not u or u.get("locked"):
            return False
        perms = set(u.get("permisos", [])) | self._permisos_de_roles(u.get("roles", []))
        return permiso in perms or "*" in perms

    def asignar_rol(self, user_id: str, rol_id: str):
        u = self.usuarios.find_by_id(user_id)
        if not u:
            return
        roles = set(u.get("roles", []))
        roles.add(rol_id)
        u["roles"] = list(roles)
        self.usuarios.upsert(u)

    def quitar_rol(self, user_id: str, rol_id: str):
        u = self.usuarios.find_by_id(user_id)
        if not u:
            return
        roles = set(u.get("roles", []))
        roles.discard(rol_id)
        u["roles"] = list(roles)
        self.usuarios.upsert(u)

    def otorgar_permiso_directo(self, user_id: str, permiso: str):
        u = self.usuarios.find_by_id(user_id)
        if not u:
            return
        perms = set(u.get("permisos", []))
        perms.add(permiso)
        u["permisos"] = list(perms)
        self.usuarios.upsert(u)

    def revocar_permiso_directo(self, user_id: str, permiso: str):
        u = self.usuarios.find_by_id(user_id)
        if not u:
            return
        perms = set(u.get("permisos", []))
        perms.discard(permiso)
        u["permisos"] = list(perms)
        self.usuarios.upsert(u)

class AuthService:
    def __init__(self, usuarios: UsuariosRepo, hasher: IHasher, tokens: ITokenService, eventbus: EventBus):
        self.usuarios = usuarios
        self.hasher = hasher
        self.tokens = tokens
        self.eventbus = eventbus
        self._intentos: Dict[str, int] = {}
        self._recuperacion: Dict[str, dict] = {}

    def autenticar(self, username: str, password: str) -> Optional[TokenSesion]:
        u = self.usuarios.find_by_username(username)
        if not u:
            self.eventbus.publish("login_fail", {"usuario": username, "motivo": "no_existe"})
            return None
        if u.get("locked"):
            self.eventbus.publish("login_fail", {"usuario": username, "motivo": "bloqueado"})
            return None

        if self.hasher.verify(password, u["hash"], u["salt"]):
            self._intentos[username] = 0
            tk = self.tokens.emitir(u["id"], ttl_minutes=30)
            self.eventbus.publish("login_ok", {"usuario": username})
            return tk
        else:
            n = self._intentos.get(username, 0) + 1
            self._intentos[username] = n
            if n >= 5:
                u["locked"] = True
                self.usuarios.upsert(u)
            self.eventbus.publish("login_fail", {"usuario": username, "motivo": "credenciales"})
            return None

    def validar_token(self, token: str) -> bool:
        return self.tokens.validar(token)

    def cerrar_sesion(self, token: str) -> None:
        self.tokens.invalidar(token)

    def cambiar_clave(self, user_id: str, old: str, new: str) -> bool:
        u = self.usuarios.find_by_id(user_id)
        if not u:
            return False
        if not self.hasher.verify(old, u["hash"], u["salt"]):
            return False
        data = self.hasher.hash(new)
        u["hash"], u["salt"] = data["hash"], data["salt"]
        self.usuarios.upsert(u)
        return True

    def iniciar_recuperacion(self, username: str) -> Optional[str]:
        u = self.usuarios.find_by_username(username)
        if not u:
            return None
        token = uuid.uuid4().hex
        self._recuperacion[token] = {"user_id": u["id"], "exp": datetime.utcnow() + timedelta(minutes=15)}
        return token

    def finalizar_recuperacion(self, token: str, new_password: str) -> bool:
        rec = self._recuperacion.get(token)
        if not rec:
            return False
        if datetime.utcnow() > rec["exp"]:
            self._recuperacion.pop(token, None)
            return False
        u = self.usuarios.find_by_id(rec["user_id"])
        if not u:
            return False
        data = self.hasher.hash(new_password)
        u["hash"], u["salt"] = data["hash"], data["salt"]
        self.usuarios.upsert(u)
        self._recuperacion.pop(token, None)
        return True

class UserService:
    def __init__(self, usuarios: UsuariosRepo, roles: RolesRepo, hasher: IHasher):
        self.usuarios = usuarios
        self.roles = roles
        self.hasher = hasher

    def crear_usuario(self, username: str, password: str, role_names: List[str]) -> str:
        if self.usuarios.find_by_username(username):
            raise ValueError("Usuario ya existe")
        data = self.hasher.hash(password)
        u = {
            "id": uuid.uuid4().hex,
            "username": username,
            "hash": data["hash"],
            "salt": data["salt"],
            "locked": False,
            "roles": [],
            "permisos": [Permiso.CUENTAS_CAMBIAR_CLAVE, Permiso.SESION_CERRAR]
        }
        for rn in role_names:
            r = self.roles.find_by_nombre(rn)
            if r:
                u["roles"].append(r["id"])
        self.usuarios.upsert(u)
        return u["id"]

    def listar_usuarios(self) -> List[dict]:
        return self.usuarios.all()

    def bloquear(self, user_id: str, lock=True):
        u = self.usuarios.find_by_id(user_id)
        if not u:
            return
        u["locked"] = lock
        self.usuarios.upsert(u)

class ServiceFactory:
    def __init__(self):
        users_default = {"usuarios": []}
        roles_default = {"roles": []}
        self.users_store = JsonStore(USERS_JSON, users_default)
        self.roles_store = JsonStore(ROLES_JSON, roles_default)

        self.usuarios = UsuariosRepo(self.users_store)
        self.roles = RolesRepo(self.roles_store)

        self.hasher = PBKDF2Hasher()
        self.tokens = SimpleTokenService()
        self.eventbus = EventBus()
        self.audit = AuditService(self.eventbus)

        self._seed_roles_if_empty()
        self._seed_users_if_empty()

        self.rbac = RBACService(self.usuarios, self.roles)
        self.auth = AuthService(self.usuarios, self.hasher, self.tokens, self.eventbus)
        self.users = UserService(self.usuarios, self.roles, self.hasher)

    def _seed_roles_if_empty(self):
        if len(self.roles.all()) == 0:
            base = [
                ("Personal", [Permiso.USUARIOS_VER, Permiso.CUENTAS_CAMBIAR_CLAVE, Permiso.SESION_CERRAR]),
                ("Jefe de Área", [Permiso.USUARIOS_VER, Permiso.USUARIOS_EDITAR, Permiso.CUENTAS_CAMBIAR_CLAVE, Permiso.SESION_CERRAR]),
                ("Gerente", [Permiso.USUARIOS_VER, Permiso.USUARIOS_EDITAR, Permiso.AUDITORIA_VER, Permiso.CUENTAS_CAMBIAR_CLAVE, Permiso.SESION_CERRAR]),
                ("Director", [Permiso.USUARIOS_VER, Permiso.AUDITORIA_VER, Permiso.CUENTAS_CAMBIAR_CLAVE, Permiso.SESION_CERRAR]),
                ("Supervisor", [Permiso.USUARIOS_VER, Permiso.AUDITORIA_VER, Permiso.CUENTAS_CAMBIAR_CLAVE, Permiso.SESION_CERRAR]),
                ("Administrador del Sistema", ["*"])
            ]
            rows = []
            for nombre, perms in base:
                rows.append({"id": uuid.uuid4().hex, "nombre": nombre, "permisos": perms})
            self.roles.save_all(rows)

    def _seed_users_if_empty(self):
        if len(self.usuarios.all()) == 0:
            for usr in LEGACY_SEED_USERS:
                username, raw_pass, rol_nombre = usr
                r = self.roles.find_by_nombre(rol_nombre)
                data = self.hasher.hash(raw_pass)
                u = {
                    "id": uuid.uuid4().hex,
                    "username": username,
                    "hash": data["hash"],
                    "salt": data["salt"],
                    "locked": False,
                    "roles": [r["id"]] if r else [],
                    "permisos": [Permiso.CUENTAS_CAMBIAR_CLAVE, Permiso.SESION_CERRAR]
                }
                self.usuarios.upsert(u)

class SistemaRBACAdapter:
    __instancia = None

    def __new__(cls):
        if cls.__instancia is None:
            cls.__instancia = super().__new__(cls)
        return cls.__instancia

    def __init__(self):
        self.factory = ServiceFactory()
        self._current_token: Optional[str] = None
        self._current_user_id: Optional[str] = None

    def registrarUsuario(self, usuario_legacy: Usuario):
        if self.factory.usuarios.find_by_username(usuario_legacy.getNombreUsuario()):
            return
        r = self.factory.roles.find_by_nombre(usuario_legacy.getRol().nombre)
        if not r:
            r = {"id": uuid.uuid4().hex, "nombre": usuario_legacy.getRol().nombre, "permisos": usuario_legacy.getRol().permisos}
            self.factory.roles.upsert(r)
        self.factory.users.crear_usuario(usuario_legacy.getNombreUsuario(), usuario_legacy._Usuario__clave, [r["nombre"]])

    def autenticar(self, nombre, clave):
        tk = self.factory.auth.autenticar(nombre, clave)
        if not tk:
            return None
        self._current_token = tk.token
        self._current_user_id = tk.user_id
        u = self.factory.usuarios.find_by_id(tk.user_id)
        rol_nombre = "Sin Rol"
        rol_perms = list(set(u.get("permisos", [])))
        rids = u.get("roles", [])
        if rids:
            r0 = self.factory.roles.find_by_id(rids[0])
            if r0:
                rol_nombre = r0["nombre"]
                rol_perms = list(set(rol_perms) | set(r0.get("permisos", [])))
        rol = Rol(rol_nombre, rol_perms)
        return Usuario(u["username"], "****", rol)

    def autorizar(self, usuario_legacy: Usuario):
        if not self._current_token or not self.factory.auth.validar_token(self._current_token):
            messagebox.showwarning("Sesión", "Tu sesión expiró. Iniciá sesión nuevamente.")
            return
        perms = usuario_legacy.getRol().permisos
        messagebox.showinfo(
            "Acceso autorizado",
            f"Bienvenido {usuario_legacy.getNombreUsuario()}!\nRol: {usuario_legacy.getRol().nombre}\n"
            f"Permisos activos: {', '.join(perms) if perms else '(ninguno)'}"
        )

    def token_actual(self) -> Optional[str]:
        return self._current_token

    def user_actual(self) -> Optional[dict]:
        if not self._current_user_id:
            return None
        return self.factory.usuarios.find_by_id(self._current_user_id)

    def cerrar_sesion(self):
        if self._current_token:
            self.factory.auth.cerrar_sesion(self._current_token)
        self._current_token = None
        self._current_user_id = None

# =============================
# ======= UI (Tkinter) ========
# =============================

rolPersonal = Rol("Personal", ["LECTURA"])
rolJefe = Rol("Jefe de Área", ["LECTURA", "EDICIÓN"])
rolGerente = Rol("Gerente", ["LECTURA", "EDICIÓN", "APROBACIÓN"])
rolDirector = Rol("Director", ["LECTURA", "EDICIÓN", "APROBACIÓN", "DECISIÓN"])
rolSupervisor = Rol("Supervisor", ["LECTURA", "CONTROL"])
rolAdmin = Rol("Administrador del Sistema", ["GESTIÓN_TOTAL"])

LEGACY_SEED_USERS = [
    ("Ange", "1234", "Personal"),
    ("Thaiana", "3355", "Administrador del Sistema"),
    ("Balthazar", "8866", "Gerente"),
    ("Agustina", "7799", "Director"),
    ("Lautaro", "1010", "Supervisor"),
    ("David", "6688", "Jefe de Área"),
]

sistema = SistemaRBACAdapter()

# ===== CONFIGURACIÓN PRINCIPAL =====
root = tk.Tk()
root.title("Sistema de Autenticación")
root.configure(bg=BG)
WIN_W, WIN_H = 1000, 600
root.geometry(f"{WIN_W}x{WIN_H}")

try:
    root.eval('tk::PlaceWindow . center')
except tk.TclError:
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    x = (sw - WIN_W) // 2
    y = (sh - WIN_H) // 3
    root.geometry(f"+{x}+{y}")

# ===== ESTILOS TTK =====
style = ttk.Style()
available = style.theme_names()
style.theme_use("clam" if "clam" in available else available[0])

# Frame base
style.configure("TFrame", background=BG)
style.configure("Dark.TFrame", background=BG)
style.configure("Card.TFrame", background=CARD_BG, relief="flat")
style.configure("CardLight.TFrame", background=CARD_BG_LIGHT, relief="flat")

# Labels
style.configure("TLabel", background=CARD_BG, foreground=TEXT, font=LABEL_FONT)
style.configure("Title.TLabel", background=BG, foreground=TEXT, font=TITLE_FONT)
style.configure("Subtitle.TLabel", background=BG, foreground=MUTED, font=SUBTITLE_FONT)
style.configure("CardLabel.TLabel", background=CARD_BG, foreground=TEXT, font=("Segoe UI", 11))
style.configure("Muted.TLabel", background=CARD_BG, foreground=MUTED, font=("Segoe UI", 9))
style.configure("Footer.TLabel", background=CARD_BG, foreground=MUTED, font=("Segoe UI", 8))

# Entry personalizado
style.configure("Modern.TEntry",
                fieldbackground=CARD_BG_LIGHT,
                foreground=TEXT,
                bordercolor=BORDER,
                lightcolor=BORDER,
                darkcolor=BORDER,
                borderwidth=1,
                relief="flat",
                padding=12)
style.map("Modern.TEntry",
          fieldbackground=[("focus", CARD_BG_LIGHT)],
          bordercolor=[("focus", PRIMARY)])

# Botones
style.configure("Primary.TButton",
                font=BUTTON_FONT,
                padding=(20, 12),
                relief="flat",
                borderwidth=0,
                background=PRIMARY,
                foreground="white")
style.map("Primary.TButton",
          background=[("active", PRIMARY_HOVER), ("pressed", PRIMARY_HOVER)])

style.configure("Secondary.TButton",
                font=("Segoe UI", 10),
                padding=(12, 8),
                relief="flat",
                background=CARD_BG_LIGHT,
                foreground=TEXT)
style.map("Secondary.TButton",
          background=[("active", BORDER)])

# Checkbutton
style.configure("Modern.TCheckbutton",
                background=CARD_BG,
                foreground=MUTED,
                font=("Segoe UI", 9))

# --------------------------
# Helpers de navegación/UI
# --------------------------

def usuario_actual_legacy() -> Optional[Usuario]:
    u = sistema.user_actual()
    if not u:
        return None
    rol_nombre = "Sin Rol"
    perms = list(set(u.get("permisos", [])))
    rids = u.get("roles", [])
    if rids:
        r0 = sistema.factory.roles.find_by_id(rids[0])
        if r0:
            rol_nombre = r0["nombre"]
            perms = list(set(perms) | set(r0.get("permisos", [])))
    return Usuario(u["username"], "****", Rol(rol_nombre, perms))

# --------------------------
# Login UI (reconstruible)
# --------------------------

# Estas refs globales permiten reconstruir/usar eventos del login
main_container = None
entry_usuario = None
entry_clave = None
btn_login = None
lbl_feedback = None

def show_login_ui():
    global main_container, entry_usuario, entry_clave, btn_login, lbl_feedback

    # Contenedor principal
    main_container = ttk.Frame(root, style="Dark.TFrame")
    main_container.pack(fill="both", expand=True)

    # División en dos columnas
    main_container.grid_columnconfigure(0, weight=1)
    main_container.grid_columnconfigure(1, weight=1)
    main_container.grid_rowconfigure(0, weight=1)

    # ===== PANEL IZQUIERDO (Branding) =====
    left_panel = tk.Frame(main_container, bg=BG)
    left_panel.grid(row=0, column=0, sticky="nsew", padx=40, pady=40)

    # Logo/Icono simulado
    logo_canvas = tk.Canvas(left_panel, width=80, height=80, bg=BG, highlightthickness=0)
    logo_canvas.pack(pady=(40, 20))
    logo_canvas.create_oval(10, 10, 70, 70, fill=PRIMARY, outline="")
    logo_canvas.create_oval(20, 20, 60, 60, fill=ACCENT, outline="")
    logo_canvas.create_oval(30, 30, 50, 50, fill=BG, outline="")

    # Títulos
    ttk.Label(left_panel, text="DISEÑO DE", style="Subtitle.TLabel").pack()
    ttk.Label(left_panel, text="Login", style="Title.TLabel").pack(pady=(0, 40))

    # Imagen decorativa (sin texto)
    decorative_frame = tk.Frame(left_panel, bg=CARD_BG, width=280, height=200)
    decorative_frame.pack(pady=20)
    decorative_frame.pack_propagate(False)
    placeholder = tk.Canvas(decorative_frame, width=240, height=160, bg=CARD_BG, highlightthickness=0)
    placeholder.place(relx=0.5, rely=0.5, anchor="center")
    placeholder.create_rectangle(10, 10, 230, 150, outline=PRIMARY)
    placeholder.create_line(10, 10, 230, 150, fill=ACCENT)
    placeholder.create_line(230, 10, 10, 150, fill=ACCENT)

    # ===== PANEL DERECHO (Formulario) =====
    right_panel = tk.Frame(main_container, bg=BG)
    right_panel.grid(row=0, column=1, sticky="nsew", padx=40, pady=40)

    # Card del formulario
    form_card = ttk.Frame(right_panel, style="Card.TFrame", padding=40)
    form_card.pack(fill="both", expand=True)

    # Título del card
    card_title = ttk.Label(form_card, text="INICIO DE SESIÓN",
                        font=("Segoe UI", 16, "bold"),
                        foreground=TEXT,
                        background=CARD_BG)
    card_title.pack(anchor="w", pady=(0, 8))

    card_subtitle = ttk.Label(form_card,
                            text="Ingresá tus credenciales para acceder",
                            style="Muted.TLabel")
    card_subtitle.pack(anchor="w", pady=(0, 30))

    # Campo Email/Usuario
    email_label = ttk.Label(form_card, text="Usuario", style="CardLabel.TLabel")
    email_label.pack(anchor="w", pady=(0, 8))

    entry_usuario = ttk.Entry(form_card, font=INPUT_FONT, style="Modern.TEntry", width=30)
    entry_usuario.pack(fill="x", pady=(0, 20))

    # Campo Contraseña
    password_label = ttk.Label(form_card, text="Contraseña", style="CardLabel.TLabel")
    password_label.pack(anchor="w", pady=(0, 8))

    password_frame = tk.Frame(form_card, bg=CARD_BG_LIGHT, height=45)
    password_frame.pack(fill="x", pady=(0, 8))
    password_frame.pack_propagate(False)

    entry_clave = tk.Entry(password_frame,
                        show="●",
                        font=INPUT_FONT,
                        bg=CARD_BG_LIGHT,
                        fg=TEXT,
                        relief="flat",
                        border=0,
                        insertbackground=TEXT)
    entry_clave.pack(side="left", fill="both", expand=True, padx=12, pady=8)

    ver_clave_var = tk.BooleanVar(value=False)
    def toggle_password():
        entry_clave.config(show="" if ver_clave_var.get() else "●")
    eye_btn = tk.Checkbutton(password_frame,
                            text="👁",
                            variable=ver_clave_var,
                            command=toggle_password,
                            bg=CARD_BG_LIGHT,
                            fg=MUTED,
                            activebackground=CARD_BG_LIGHT,
                            activeforeground=TEXT,
                            selectcolor=CARD_BG_LIGHT,
                            relief="flat",
                            border=0,
                            font=("Segoe UI", 12))
    eye_btn.pack(side="right", padx=8)

    # Checkbox recordar
    remember_check = ttk.Checkbutton(form_card,
                                    text="Recordar mis credenciales",
                                    style="Modern.TCheckbutton")
    remember_check.pack(anchor="w", pady=(0, 8))

    # Link olvidé contraseña (decorativo)
    forgot_link = tk.Label(form_card,
                        text="¿Olvidaste tu contraseña?",
                        fg=PRIMARY,
                        bg=CARD_BG,
                        font=("Segoe UI", 9, "underline"),
                        cursor="hand2")
    forgot_link.pack(anchor="w", pady=(0, 24))

    # Feedback
    lbl_feedback = tk.Label(form_card,
                            text="",
                            fg=ERROR_FG,
                            bg=CARD_BG,
                            font=("Segoe UI", 9))
    lbl_feedback.pack(fill="x", pady=(0, 12))

    def login(*_):
        nombre = entry_usuario.get().strip()
        clave = entry_clave.get()

        if not nombre or not clave:
            lbl_feedback.config(text="⚠ Por favor completá todos los campos", fg=ERROR_FG)
            return

        btn_login.config(text="Validando...", state="disabled")
        root.update()
        root.after(500)

        usuarioAutenticado = sistema.autenticar(nombre, clave)

        if usuarioAutenticado:
            btn_login.config(text="✓ Acceso concedido")
            lbl_feedback.config(text="✓ Inicio de sesión exitoso", fg=SUCCESS_FG)

            def _go():
                sistema.autorizar(usuarioAutenticado)
                abrir_dashboard(usuarioAutenticado)
                try:
                    if main_container and main_container.winfo_exists():
                        main_container.destroy()  # cerrar login al abrir dashboard
                except Exception:
                    pass
            root.after(800, _go)
        else:
            btn_login.config(text="Iniciar sesión", state="normal")
            lbl_feedback.config(text="⚠ Credenciales incorrectas o usuario bloqueado", fg=ERROR_FG)
            entry_clave.delete(0, tk.END)

    # Botón de login
    btn_frame = tk.Frame(form_card, bg=CARD_BG)
    btn_frame.pack(fill="x", pady=(12, 0))

    btn_login = tk.Button(btn_frame,
                        text="Iniciar sesión",
                        font=BUTTON_FONT,
                        bg=PRIMARY,
                        fg="white",
                        activebackground=PRIMARY_HOVER,
                        activeforeground="white",
                        relief="flat",
                        cursor="hand2",
                        border=0,
                        pady=14,
                        command=login)
    btn_login.pack(fill="x")
    btn_login.bind("<Enter>", lambda e: btn_login.config(bg=PRIMARY_HOVER))
    btn_login.bind("<Leave>", lambda e: btn_login.config(bg=PRIMARY))
    btn_login.bind("<space>", lambda e: login())

    # Footer
    footer_separator = tk.Frame(form_card, bg=BORDER, height=1)
    footer_separator.pack(fill="x", pady=(30, 16))

    footer_text = ttk.Label(form_card,
                            text="Sistema seguro con RBAC • Auditoría • Encriptación robusta",
                            style="Footer.TLabel")
    footer_text.pack()

    # UX: limpiar feedback al tipear
    entry_usuario.bind("<Key>", lambda e: lbl_feedback.config(text=""))
    entry_clave.bind("<Key>", lambda e: lbl_feedback.config(text=""))

    entry_usuario.focus()
    root.bind("<Return>", login)

# ===== DASHBOARD (Post-login) =====
def abrir_dashboard(usuario_legacy: Usuario):
    dash = tk.Toplevel(root)
    dash.title(f"Panel de Control - {usuario_legacy.getNombreUsuario()}")
    dash.configure(bg=BG)
    dash.geometry("900x600")

    # Header
    header_frame = tk.Frame(dash, bg=CARD_BG, height=80)
    header_frame.pack(fill="x", side="top")
    header_frame.pack_propagate(False)

    header_content = tk.Frame(header_frame, bg=CARD_BG)
    header_content.pack(fill="both", expand=True, padx=30, pady=15)

    title_dash = tk.Label(header_content,
                        text="Panel de Control",
                        font=("Segoe UI", 18, "bold"),
                        fg=TEXT,
                        bg=CARD_BG)
    title_dash.pack(side="left")

    user_info = tk.Label(header_content,
                        text=f"👤 {usuario_legacy.getNombreUsuario()} • {usuario_legacy.getRol().nombre}",
                        font=("Segoe UI", 11),
                        fg=MUTED,
                        bg=CARD_BG)
    user_info.pack(side="right")

    # Contenido
    content_frame = tk.Frame(dash, bg=BG)
    content_frame.pack(fill="both", expand=True, padx=30, pady=20)

    current = sistema.user_actual()
    def can(p):
        return current is not None and SistemaLoginHelpers.has_perm_current(p)

    def create_action_card(parent, title, desc, icon, command, perm=None):
        card = tk.Frame(parent, bg=CARD_BG, relief="flat", borderwidth=1)
        card.pack(side="left", padx=10, pady=10, ipadx=20, ipady=20)

        icon_label = tk.Label(card, text=icon, font=("Segoe UI", 32), bg=CARD_BG, fg=PRIMARY)
        icon_label.pack(pady=(10, 5))

        title_label = tk.Label(card, text=title, font=("Segoe UI", 12, "bold"), bg=CARD_BG, fg=TEXT)
        title_label.pack()

        desc_label = tk.Label(card, text=desc, font=("Segoe UI", 9), bg=CARD_BG, fg=MUTED, wraplength=120)
        desc_label.pack(pady=(5, 15))

        if perm and not can(perm):
            btn = tk.Button(card, text="Sin acceso", font=("Segoe UI", 9), bg=BORDER, fg=MUTED,
                            relief="flat", state="disabled", cursor="arrow", pady=8, padx=20)
        else:
            btn = tk.Button(card, text="Abrir", font=("Segoe UI", 9, "bold"), bg=PRIMARY, fg="white",
                            activebackground=PRIMARY_HOVER, activeforeground="white",
                            relief="flat", cursor="hand2", command=command, pady=8, padx=20)
        btn.pack()

        return card

    row1 = tk.Frame(content_frame, bg=BG); row1.pack(fill="x", pady=10)
    row2 = tk.Frame(content_frame, bg=BG); row2.pack(fill="x", pady=10)

    create_action_card(row1, "Usuarios", "Gestionar usuarios del sistema", "👥",
                       lambda: ui_usuarios(dash), Permiso.USUARIOS_VER)
    create_action_card(row1, "Roles", "Administrar roles y permisos", "🔐",
                       lambda: ui_roles(dash), Permiso.ROLES_VER)
    create_action_card(row1, "Auditoría", "Ver registros de actividad", "📊",
                       lambda: ui_auditoria(dash), Permiso.AUDITORIA_VER)

    create_action_card(row2, "Mi Cuenta", "Cambiar contraseña", "⚙️",
                       lambda: ui_cambiar_clave(dash), Permiso.CUENTAS_CAMBIAR_CLAVE)
    create_action_card(row2, "Salir", "Cerrar sesión actual", "🚪",
                       do_logout, Permiso.SESION_CERRAR)

def do_logout():
    sistema.cerrar_sesion()
    # Cerrar cualquier Toplevel abierto
    for w in root.winfo_children():
        if isinstance(w, tk.Toplevel):
            try:
                w.destroy()
            except Exception:
                pass
    messagebox.showinfo("Sesión", "Sesión cerrada correctamente.")
    # Limpiar raíz y reconstruir login
    for child in root.winfo_children():
        if child != root:
            try:
                child.destroy()
            except Exception:
                pass
    show_login_ui()

def ui_auditoria(parent):
    try:
        parent.destroy()
    except Exception:
        pass

    win = tk.Toplevel(root)
    win.title("Auditoría del Sistema")
    win.configure(bg=BG)
    win.geometry("800x500")

    frame = tk.Frame(win, bg=BG)
    frame.pack(fill="both", expand=True, padx=20, pady=20)

    title = tk.Label(frame, text="Registro de Auditoría", font=("Segoe UI", 16, "bold"),
                    fg=TEXT, bg=BG)
    title.pack(anchor="w", pady=(0, 15))

    tree_frame = tk.Frame(frame, bg=CARD_BG)
    tree_frame.pack(fill="both", expand=True)

    tree = ttk.Treeview(tree_frame, columns=("ts","usuario","accion","resultado","detalle"),
                       show="headings", height=15)
    for c, w in [("ts", 150), ("usuario", 100), ("accion", 150), ("resultado", 80), ("detalle", 200)]:
        tree.heading(c, text=c.upper()); tree.column(c, width=w)
    tree.pack(fill="both", expand=True, padx=10, pady=10)

    eventos = sistema.factory.audit.listar_eventos()
    for e in eventos:
        tree.insert("", "end", values=(e["timestamp"], e["usuario"], e["accion"],
                                      e["resultado"], json.dumps(e.get("detalle",{}), ensure_ascii=False)))

    info = tk.Label(frame, text=f"Total: {len(eventos)} eventos registrados",
                   font=("Segoe UI", 9), fg=MUTED, bg=BG)
    info.pack(anchor="w", pady=(10, 0))

    def volver_al_panel():
        ua = usuario_actual_legacy()
        if ua:
            try:
                win.destroy()
            except Exception:
                pass
            abrir_dashboard(ua)

    back_bar = tk.Frame(frame, bg=BG)
    back_bar.pack(fill="x", pady=(12, 0))
    tk.Button(back_bar, text="⬅ Volver al Panel", font=("Segoe UI", 10),
              bg=CARD_BG_LIGHT, fg=TEXT, relief="flat", cursor="hand2",
              command=volver_al_panel, pady=10, padx=16).pack(side="left")

def ui_usuarios(parent):
    try:
        parent.destroy()
    except Exception:
        pass

    win = tk.Toplevel(root)
    win.title("Gestión de Usuarios")
    win.configure(bg=BG)
    win.geometry("900x550")

    frame = tk.Frame(win, bg=BG)
    frame.pack(fill="both", expand=True, padx=20, pady=20)

    title = tk.Label(frame, text="Usuarios del Sistema", font=("Segoe UI", 16, "bold"),
                    fg=TEXT, bg=BG)
    title.pack(anchor="w", pady=(0, 15))

    tree_frame = tk.Frame(frame, bg=CARD_BG)
    tree_frame.pack(fill="both", expand=True)

    cols = ("id","username","locked","roles","permisos")
    tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=12)
    for c in cols:
        tree.heading(c, text=c.upper())
    tree.pack(fill="both", expand=True, padx=10, pady=10)

    def refresh():
        for i in tree.get_children():
            tree.delete(i)
        for u in sistema.factory.users.listar_usuarios():
            roles = [sistema.factory.roles.find_by_id(r)["nombre"] for r in u.get("roles", [])
                    if sistema.factory.roles.find_by_id(r)]
            tree.insert("", "end", values=(u["id"][:8], u["username"],
                                          "🔒" if u["locked"] else "✓",
                                          ", ".join(roles),
                                          str(len(u.get("permisos",[])))))

    def crear_usuario():
        if not SistemaLoginHelpers.has_perm_current(Permiso.USUARIOS_CREAR):
            SistemaLoginHelpers.denegar("USUARIOS.CREAR"); return
        username = simpledialog.askstring("Nuevo usuario", "Username:")
        if not username: return
        password = simpledialog.askstring("Nuevo usuario", "Password (temporal):", show="*")
        if not password: return
        rol_nombre = simpledialog.askstring("Nuevo usuario", "Rol inicial:")
        try:
            sistema.factory.users.crear_usuario(username, password, [rol_nombre] if rol_nombre else [])
            sistema.factory.eventbus.publish("accion", {"usuario": sistema.user_actual().get("username","-"),
                                                       "accion": "USUARIOS.CREAR", "resultado": "OK",
                                                       "detalle": {"username": username}})
            refresh()
            messagebox.showinfo("Usuarios", "Usuario creado exitosamente.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def bloquear_usuario():
        if not SistemaLoginHelpers.has_perm_current(Permiso.USUARIOS_BLOQUEAR):
            SistemaLoginHelpers.denegar(Permiso.USUARIOS_BLOQUEAR); return
        sel = tree.selection()
        if not sel: return
        uid_short = tree.item(sel[0])["values"][0]
        for u in sistema.factory.users.listar_usuarios():
            if u["id"].startswith(uid_short):
                sistema.factory.users.bloquear(u["id"], True)
                sistema.factory.eventbus.publish("accion", {"usuario": sistema.user_actual().get("username","-"),
                                                           "accion": "USUARIOS.BLOQUEAR", "resultado": "OK",
                                                           "detalle": {"user_id": u["id"]}})
                refresh(); break

    def desbloquear_usuario():
        sel = tree.selection()
        if not sel: return
        uid_short = tree.item(sel[0])["values"][0]
        for u in sistema.factory.users.listar_usuarios():
            if u["id"].startswith(uid_short):
                sistema.factory.users.bloquear(u["id"], False)
                sistema.factory.eventbus.publish("accion", {"usuario": sistema.user_actual().get("username","-"),
                                                           "accion": "USUARIOS.DESBLOQUEAR", "resultado": "OK",
                                                           "detalle": {"user_id": u["id"]}})
                refresh(); break

    btns = tk.Frame(frame, bg=BG)
    btns.pack(fill="x", pady=(15, 0))

    tk.Button(btns, text="➕ Crear Usuario", font=("Segoe UI", 10, "bold"), bg=PRIMARY, fg="white",
              activebackground=PRIMARY_HOVER, relief="flat", cursor="hand2",
              command=crear_usuario, pady=10, padx=20).pack(side="left", padx=5)
    tk.Button(btns, text="🔒 Bloquear", font=("Segoe UI", 10), bg=CARD_BG_LIGHT, fg=TEXT,
              relief="flat", cursor="hand2", command=bloquear_usuario, pady=10, padx=20).pack(side="left", padx=5)
    tk.Button(btns, text="🔓 Desbloquear", font=("Segoe UI", 10), bg=CARD_BG_LIGHT, fg=TEXT,
              relief="flat", cursor="hand2", command=desbloquear_usuario, pady=10, padx=20).pack(side="left", padx=5)

    refresh()

    def volver_al_panel():
        ua = usuario_actual_legacy()
        if ua:
            try:
                win.destroy()
            except Exception:
                pass
            abrir_dashboard(ua)

    back_bar = tk.Frame(frame, bg=BG)
    back_bar.pack(fill="x", pady=(12, 0))
    tk.Button(back_bar, text="⬅ Volver al Panel", font=("Segoe UI", 10),
              bg=CARD_BG_LIGHT, fg=TEXT, relief="flat", cursor="hand2",
              command=volver_al_panel, pady=10, padx=16).pack(side="left")

def ui_roles(parent):
    try:
        parent.destroy()
    except Exception:
        pass

    win = tk.Toplevel(root)
    win.title("Gestión de Roles y Permisos")
    win.configure(bg=BG)
    win.geometry("800x550")

    frame = tk.Frame(win, bg=BG)
    frame.pack(fill="both", expand=True, padx=20, pady=20)

    title = tk.Label(frame, text="Roles y Permisos", font=("Segoe UI", 16, "bold"),
                    fg=TEXT, bg=BG)
    title.pack(anchor="w", pady=(0, 15))

    tree_frame = tk.Frame(frame, bg=CARD_BG)
    tree_frame.pack(fill="both", expand=True)

    cols = ("id","nombre","permisos")
    tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=12)
    for c in cols:
        tree.heading(c, text=c.upper())
    tree.pack(fill="both", expand=True, padx=10, pady=10)

    def refresh():
        for i in tree.get_children():
            tree.delete(i)
        for r in sistema.factory.roles.all():
            tree.insert("", "end", values=(r["id"][:8], r["nombre"],
                                          str(len(r.get("permisos",[])))))

    def crear_rol():
        if not SistemaLoginHelpers.has_perm_current(Permiso.ROLES_EDITAR):
            SistemaLoginHelpers.denegar(Permiso.ROLES_EDITAR); return
        nombre = simpledialog.askstring("Nuevo rol", "Nombre del rol:")
        if not nombre: return
        perms = simpledialog.askstring("Nuevo rol", "Permisos (separados por coma):")
        permisos = [p.strip() for p in (perms or "").split(",") if p.strip()]
        r = {"id": uuid.uuid4().hex, "nombre": nombre, "permisos": permisos}
        sistema.factory.roles.upsert(r)
        sistema.factory.eventbus.publish("accion", {"usuario": sistema.user_actual().get("username","-"),
                                                   "accion": "ROLES.CREAR", "resultado": "OK",
                                                   "detalle": {"rol": nombre}})
        refresh()

    def editar_permisos():
        if not SistemaLoginHelpers.has_perm_current(Permiso.PERMISOS_EDITAR):
            SistemaLoginHelpers.denegar(Permiso.PERMISOS_EDITAR); return
        sel = tree.selection()
        if not sel: return
        rid_short = tree.item(sel[0])["values"][0]
        for r in sistema.factory.roles.all():
            if r["id"].startswith(rid_short):
                actual = ", ".join(r.get("permisos", []))
                nuevo = simpledialog.askstring("Editar permisos",
                                              f"Permisos actuales:\n{actual}\n\nNuevos (separados por coma):")
                if nuevo is None: return
                r["permisos"] = [p.strip() for p in nuevo.split(",") if p.strip()]
                sistema.factory.roles.upsert(r)
                sistema.factory.eventbus.publish("accion", {"usuario": sistema.user_actual().get("username","-"),
                                                           "accion": "PERMISOS.EDITAR", "resultado": "OK",
                                                           "detalle": {"rol": r["nombre"]}})
                refresh(); break

    btns = tk.Frame(frame, bg=BG)
    btns.pack(fill="x", pady=(15, 0))

    tk.Button(btns, text="➕ Crear Rol", font=("Segoe UI", 10, "bold"), bg=PRIMARY, fg="white",
              activebackground=PRIMARY_HOVER, relief="flat", cursor="hand2",
              command=crear_rol, pady=10, padx=20).pack(side="left", padx=5)
    tk.Button(btns, text="✏️ Editar Permisos", font=("Segoe UI", 10), bg=CARD_BG_LIGHT, fg=TEXT,
              relief="flat", cursor="hand2", command=editar_permisos, pady=10, padx=20).pack(side="left", padx=5)

    refresh()

    def volver_al_panel():
        ua = usuario_actual_legacy()
        if ua:
            try:
                win.destroy()
            except Exception:
                pass
            abrir_dashboard(ua)

    back_bar = tk.Frame(frame, bg=BG)
    back_bar.pack(fill="x", pady=(12, 0))
    tk.Button(back_bar, text="⬅ Volver al Panel", font=("Segoe UI", 10),
              bg=CARD_BG_LIGHT, fg=TEXT, relief="flat", cursor="hand2",
              command=volver_al_panel, pady=10, padx=16).pack(side="left")

def ui_cambiar_clave(parent):
    user = sistema.user_actual()
    if not user:
        messagebox.showwarning("Sesión", "No hay sesión activa.")
        return
    old = simpledialog.askstring("Cambiar contraseña", "Contraseña actual:", show="*")
    if old is None: return
    new = simpledialog.askstring("Cambiar contraseña", "Nueva contraseña:", show="*")
    if new is None: return
    ok = sistema.factory.auth.cambiar_clave(user["id"], old, new)
    if ok:
        messagebox.showinfo("Cuenta", "Contraseña cambiada exitosamente.")
        sistema.factory.eventbus.publish("accion", {"usuario": user.get("username","-"),
                                                   "accion": "CUENTAS.CAMBIAR_CLAVE", "resultado": "OK"})
    else:
        messagebox.showerror("Cuenta", "No se pudo cambiar la contraseña. Verificá la actual.")

class SistemaLoginHelpers:
    @staticmethod
    def has_perm_current(perm: str) -> bool:
        user = sistema.user_actual()
        if not user:
            return False
        return sistema.factory.rbac.has_perm(user["id"], perm)

    @staticmethod
    def denegar(perm: str):
        user = sistema.user_actual()
        sistema.factory.eventbus.publish("permiso_denegado",
                                        {"usuario": user.get("username","-") if user else "-",
                                         "permiso": perm})
        messagebox.showerror("Permiso denegado",
                           f"No tenés el permiso requerido: {perm}")

# Registrar usuarios semilla
for username, password, rol_nombre in LEGACY_SEED_USERS:
    sistema.registrarUsuario(Usuario(username, password, Rol(rol_nombre, [])))

# Mostrar login
show_login_ui()

root.mainloop()