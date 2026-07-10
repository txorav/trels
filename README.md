<div align="center">
  <img src="trels.png" alt="Trels Logo" width="128">
</div>

# Trels — Lightweight Local DNS Manager & Reverse Proxy

![GitHub Release](https://img.shields.io/github/v/release/txorav/trels)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/txorav/trels/total)
![GitHub License](https://img.shields.io/github/license/txorav/trels)


Trels is a secure, cross-platform (Windows & Linux) local domain router and reverse proxy. It allows you to map custom domain names (e.g. `app.local`) to target local ports (e.g. `:3000`) instantly at the operating system level, acting as a zero-config local development router.

The backend is built in high-performance Go, while the frontend is a beautifully polished, single-page admin dashboard styled with modern Shadcn/ui tokens using vanilla HTML/CSS/JS.

---

## Key Features

- **Real-Time Traffic Dashboard**: Visualize requests/second and bandwidth (in/out) globally and per-domain via live `Chart.js` line charts.
- **Collapsible Sidebar**: Compact sidebar that transitions smoothly with icons and supports full responsive layouts.
- **Omnibar Search**: Global search bar to filter mappings, ports, and configuration fields instantly.
- **Port Scanner Engine**: Scans active ports on your system (using `netstat` or `ss`) to suggest currently running local applications when creating a mapping. Warns you if you map a closed port.
- **Zero-Config HTTPS (Auto CA Trust)**: Generates self-signed wildcard root certificates on startup and automatically registers them with the operating system's Trusted Root Certification Authority store (Windows `certutil` / Linux `update-ca-certificates`).
- **Database Encryption (AES-256-GCM)**: Mappings are stored in `records.json` and encrypted at rest. The key is derived dynamically using your machine's hardware ID so the database cannot be stolen and decrypted on another computer.
- **Database Portability**: Built-in plaintext Export and Import JSON features let you backup, merge, or transfer configurations between machines securely.
- **Per-Mapping HTTP Basic Auth**: Secure individual local domains with standard Basic Authentication credentials evaluated in constant-time.
- **Sleek Dark Mode**: Full custom dark and light theme toggles with persisted theme settings.

---

## Project Structure

```
├── .github/workflows/   # CI/CD configurations
├── backend/             # Go reverse proxy and API backend
│   ├── main.go          # Main entrypoint
│   └── main_test.go     # Go tests
├── build/               # Automation scripts and outputs
│   ├── bin/             # Ignored binary output folder
│   ├── build.bat        # Windows build tool
│   └── build.sh         # Linux build tool
├── frontend/            # Frontend interfaces
│   └── admin/           # Embedded admin panel assets (vanilla JS/CSS/HTML)
├── LICENSE              # MIT License
├── README.md            # You are here
└── .gitignore           # Git ignore list
```

---

## Prerequisites

- **Go**: Required to compile the project (Go 1.20+ recommended). Download from [go.dev](https://go.dev/dl/).
- **OS Privileges**: You **must** run the compiled binary as **Administrator** (Windows) or **root** (Linux) so that the application can:
  - Modify the system `hosts` file.
  - Bind to privileged ports `80` (HTTP) and `443` (HTTPS).
  - Register SSL certificates in the OS-level trust store.

---

## Installation

Download the latest version from the [Releases page](https://github.com/txorav/trels/releases).

### Windows

Download and run the **`trels-setup-amd64.exe`** (or `arm64`) installer. It will automatically install Trels into `C:\Program Files\Trels` and create a Start Menu shortcut.

Alternatively, download the `.zip` archive and extract it manually. Note: You must run the executable as Administrator.

### Linux (Debian / Ubuntu)

Download the `.deb` package and install it using `dpkg`:
```bash
sudo dpkg -i trels_*_amd64.deb
```
Enable and start the background service:
```bash
sudo systemctl enable --now trels
```

### Linux (RHEL / Fedora / CentOS)

Download the `.rpm` package and install it using `rpm`:
```bash
sudo rpm -i trels_*_amd64.rpm
sudo systemctl enable --now trels
```

---

## Building from Source

We provide automated build scripts that handle compiling the Go binary and embedding static assets.

### Windows (PowerShell / CMD)
1. Double-click or run `build/build.bat` in a terminal.
2. The compiled binary will be placed at `build/bin/trels.exe`.
3. Open a shell as **Administrator** and run:
   ```cmd
   .\build\bin\trels.exe
   ```
4. Access the admin dashboard at `http://127.0.0.1:8080` (Default Credentials: `admin` / `admin`).

### Linux / macOS
1. Open a terminal and run the build script:
   ```bash
   ./build/build.sh
   ```
2. The compiled binary will be placed at `build/bin/trels`.
3. Run the binary with `sudo` privileges:
   ```bash
   sudo ./build/bin/trels
   ```
4. Access the admin dashboard at `http://127.0.0.1:8080`.

---

## Security Specifications

### Machine-Level Key Derivation
To lock the configuration database to the local environment, the 32-byte encryption key is hashed from:
- **Windows**: The HKLM Registry value `MachineGuid`.
- **Linux**: The OS file `/etc/machine-id` or `/var/lib/dbus/machine-id`.

### Constant-Time Evaluations
To prevent timing attack exploits, Basic Authentication headers for both the Admin Panel and mapped domains are validated using Go's `crypto/subtle.ConstantTimeCompare`.

---

## License

This project is open-source and licensed under the [MIT License](LICENSE).
