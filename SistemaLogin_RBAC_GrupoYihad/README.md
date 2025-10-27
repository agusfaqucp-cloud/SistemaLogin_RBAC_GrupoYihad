# 🧠 Sistema de Login y Control de Acceso (RBAC)
### Proyecto del Grupo Yihad — Facultad de Ingeniería en Sistemas

Este proyecto implementa un **sistema de autenticación y autorización con control de acceso basado en roles (RBAC)**, desarrollado en **Python + Tkinter** aplicando principios de **POO, SOLID** y **patrones de diseño**.

## 👥 Equipo de desarrollo
| Integrante  | Rol dentro del grupo |
|--------------|----------------------|
| **Yihad** | Líder del Proyecto (Project Manager) |
| **Agustina** | Documentadora Técnica |
| **Thaiana** | Frontend Developer (UI/UX) |
| **Balthazar** | Backend Developer |
| **David / Lautaro / Ange** | Colaboradores y testers |

## 🚀 Funcionalidades principales
- Inicio de sesión seguro con bloqueo tras 5 intentos fallidos.
- Control de acceso basado en roles y permisos individuales (RBAC).
- Gestión de usuarios y roles con interfaz gráfica.
- Auditoría de eventos (login, bloqueos, cambios de clave).
- Cifrado de contraseñas PBKDF2 + SHA256.
- Interfaz moderna con Tkinter.
- Principios POO, SOLID y patrones (Factory, Repository, Singleton, Strategy, Observer).

## 🧱 Arquitectura del sistema
1. Dominio: `Usuario`, `Rol`, `Permiso`, `TokenSesion`.
2. Aplicación: `AuthService`, `RBACService`, `AuditService`, `UserService`.
3. Infraestructura: `JsonStore`, `Repositorios`, `EventBus`.
4. Presentación: interfaz Tkinter (`Login`, `Dashboard`, `Gestión`, `Auditoría`).

## ⚙️ Requisitos
- Python 3.10+
- Librerías incluidas por defecto: tkinter, hashlib, hmac, json, uuid, datetime

## 🖥️ Ejecución
1. Clonar o descargar este repositorio.
2. Ejecutar desde consola o VSCode:
   ```bash
   python ./src/login_definitivo.py
   ```

## 👤 Usuarios de prueba
| Usuario | Contraseña | Rol |
|----------|-------------|-----|
| Ange | 1234 | Personal |
| Thaiana | 3355 | Administrador del Sistema |
| Balthazar | 8866 | Gerente |
| Agustina | 7799 | Director |
| Lautaro | 1010 | Supervisor |
| David | 6688 | Jefe de Área |

## 📜 Licencia
MIT
