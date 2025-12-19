# Informe Técnico Completo: Sistema de Criptografía y Seguridad

## Información del Proyecto

| Atributo | Valor |
|----------|-------|
| **Nombre** | CryptoSecurity |
| **Framework** | Django 5.2.7 |
| **Lenguaje** | Python 3.13 |
| **Dependencias** | pycryptodome 3.23.0 |
| **Ubicación** | `C:\Users\JEanpa\.gemini\antigravity\scratch\crypto_security` |
| **Puerto** | 8000 |

---

## 1. Arquitectura del Sistema

### 1.1 Estructura de Directorios

```
crypto_security/
├── manage.py                      # Script de gestión Django
├── crypto_security/               # Configuración del proyecto
│   ├── settings.py               # Configuración general
│   ├── urls.py                   # URLs principales
│   └── wsgi.py                   # WSGI para despliegue
├── crypto_app/                    # Aplicación principal
│   ├── algorithms/               # Módulos de cifrado
│   │   ├── __init__.py
│   │   ├── caesar.py             # Cifrado César
│   │   ├── lfsr.py               # LFSR (Acarreo)
│   │   ├── aes_demo.py           # AES
│   │   ├── custom_symmetric.py   # CipherX
│   │   └── custom_asymmetric.py  # SimpleRSA
│   ├── authentication/           # Autenticación de mensajes
│   │   ├── __init__.py
│   │   └── message_auth.py       # HMAC, Firmas digitales
│   ├── attacks/                  # Simulación de ataques
│   │   ├── __init__.py
│   │   ├── brute_force.py        # Fuerza bruta
│   │   └── mitm_demo.py          # Man-in-the-Middle
│   ├── templates/crypto_app/     # Plantillas HTML
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── algorithms.html
│   │   ├── authentication.html
│   │   └── attacks.html
│   ├── views.py                  # Vistas y API
│   └── urls.py                   # Rutas de la app
└── docs/
    └── informe.md                # Documentación
```

### 1.2 Diagrama de Flujo de Datos

```
┌─────────────────────────────────────────────────────────────────┐
│                        USUARIO (Browser)                         │
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │    HTTP Request       │
                    │  (GET/POST JSON)      │
                    ▼                       ▼
            ┌───────────────┐       ┌───────────────┐
            │  Vistas HTML  │       │   API REST    │
            │  (Templates)  │       │   (JSON)      │
            └───────────────┘       └───────────────┘
                    │                       │
                    └───────────┬───────────┘
                                │
                    ┌───────────┴───────────┐
                    │      views.py          │
                    │   (Controladores)      │
                    └───────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│  algorithms/  │       │authentication/│       │   attacks/    │
│               │       │               │       │               │
│ • caesar.py   │       │• message_auth │       │• brute_force  │
│ • lfsr.py     │       │  .py          │       │  .py          │
│ • aes_demo.py │       │               │       │• mitm_demo.py │
│ • custom_*    │       │               │       │               │
└───────────────┘       └───────────────┘       └───────────────┘
```

---

## 2. Vistas HTML (Templates)

### 2.1 Vista Principal: `index.html`

**URL:** `/`  
**Función:** `views.index`  
**Propósito:** Dashboard con resumen del sistema y demo rápida

**Secciones:**
1. **Hero** - Título y descripción del sistema
2. **Grid de 3 Cards** - Enlaces a módulos principales
3. **Demo Rápida César** - Formulario interactivo
4. **Conceptos Clave** - Definiciones educativas

**Código de Vista:**
```python
def index(request):
    """Vista principal - Dashboard."""
    return render(request, 'crypto_app/index.html')
```

---

### 2.2 Vista de Algoritmos: `algorithms.html`

**URL:** `/algorithms/`  
**Función:** `views.algorithms_view`  
**Propósito:** Demostración interactiva de todos los algoritmos

**Secciones:**
| Sección | Algoritmo | Funcionalidades |
|---------|-----------|-----------------|
| Card 1 | César | Cifrar, Descifrar |
| Card 2 | LFSR | Cifrar, Visualizar proceso |
| Card 3 | AES | Cifrar (CBC/ECB/CTR), Info técnica |
| Card 4 | CipherX | Cifrar, Descifrar, Info |
| Card 5 | SimpleRSA | Generar claves, Cifrar, Visualizar |
| Tabla | Comparativa | Ventajas/desventajas de algoritmos |

**Código de Vista:**
```python
def algorithms_view(request):
    """Vista de algoritmos criptográficos."""
    algorithms_info = {
        'caesar': {'name': 'Cifrado César', 'type': 'Sustitución monoalfabética'},
        'lfsr': {'name': 'LFSR (Acarreo)', 'type': 'Cifrado de flujo'},
        'aes': AESDemo.get_algorithm_info(),
        'cipherx': CipherX.get_algorithm_info(),
        'simplersa': SimpleRSA.get_algorithm_info()
    }
    return render(request, 'crypto_app/algorithms.html', {'algorithms': algorithms_info})
```

---

### 2.3 Vista de Autenticación: `authentication.html`

**URL:** `/authentication/`  
**Función:** `views.authentication_view`  
**Propósito:** Verificación de origen e integridad de mensajes

**Secciones:**
| Sección | Funcionalidad | Descripción |
|---------|---------------|-------------|
| HMAC | Crear MAC, Autenticar | Hash-based Message Authentication |
| Firma Digital | Firmar, Explicar | RSA-SHA256 |
| Verificación Origen | Simular canal | Demostración paso a paso |
| Demo Integridad | Crear/Verificar MAC | Detectar alteraciones |
| Comparativa | Tabla | HMAC vs Firma Digital |

**Código de Vista:**
```python
def authentication_view(request):
    """Vista de autenticación de mensajes."""
    hmac_info = HMACAuthenticator.explain_hmac()
    signature_info = DigitalSignature.explain_digital_signature()
    comparison = MessageOriginVerifier.compare_methods()
    return render(request, 'crypto_app/authentication.html', {...})
```

---

### 2.4 Vista de Ataques: `attacks.html`

**URL:** `/attacks/`  
**Función:** `views.attacks_view`  
**Propósito:** Simulación de ataques y contramedidas

**Secciones:**
| Sección | Ataque | Funcionalidades |
|---------|--------|-----------------|
| Fuerza Bruta | César, Estimador, Frecuencia | 3 tabs con diferentes demos |
| MITM | 3 escenarios | Sin cifrado, DH, Con firma |
| Kali Linux | 6 herramientas | Hashcat, John, Hydra, etc. |
| Descifrar | Metodología | Pasos de análisis |
| Defensas | Tabla | Contramedidas por ataque |

**Código de Vista:**
```python
def attacks_view(request):
    """Vista de ataques criptográficos."""
    bf_info = BruteForceAttack.get_attack_info()
    mitm_info = MITMSimulation.get_mitm_info()
    return render(request, 'crypto_app/attacks.html', {...})
```

---

## 3. API REST Endpoints

### 3.1 Endpoints de Algoritmos

#### POST `/api/caesar/`

**Descripción:** Operaciones con cifrado César

**Request Body:**
```json
{
    "action": "encrypt|decrypt|brute_force|frequency",
    "text": "Mensaje a procesar",
    "shift": 3
}
```

**Ejemplo - Cifrar:**
```json
// Request
{"action": "encrypt", "text": "Hola Mundo", "shift": 3}

// Response
{
    "success": true,
    "action": "encrypt",
    "input": "Hola Mundo",
    "shift": 3,
    "result": "Krod Pxqgr"
}
```

**Ejemplo - Fuerza Bruta:**
```json
// Request
{"action": "brute_force", "text": "Krod Pxqgr"}

// Response
{
    "success": true,
    "result": [
        {"shift": 3, "decrypted": "Hola Mundo", "frequency_score": 45.2},
        {"shift": 10, "decrypted": "Axet Fngwx", "frequency_score": 12.1},
        ...
    ]
}
```

---

#### POST `/api/lfsr/`

**Descripción:** Cifrado de flujo LFSR

**Request Body:**
```json
{
    "action": "encrypt|decrypt|visualize",
    "text": "Mensaje",
    "seed": "ACE1"
}
```

**Ejemplo - Cifrar:**
```json
// Request
{"action": "encrypt", "text": "Secreto", "seed": "ACE1"}

// Response
{
    "success": true,
    "action": "encrypt",
    "seed": "0xace1",
    "result": {
        "ciphertext": "a4b2c1d0...",
        "keystream": "f1e2d3c4..."
    }
}
```

**Ejemplo - Visualizar:**
```json
// Response
{
    "result": {
        "seed": 44257,
        "taps": [15, 13, 12, 10],
        "register_size": 16,
        "steps": [
            {
                "position": 0,
                "char": "S",
                "plaintext_byte": "01010011",
                "keystream_byte": "10101100",
                "cipher_byte": "11111111",
                "lfsr_state": "1010110011100001"
            },
            ...
        ]
    }
}
```

---

#### POST `/api/aes/`

**Descripción:** Cifrado AES con múltiples modos

**Request Body:**
```json
{
    "action": "encrypt|decrypt|info|subbytes",
    "text": "Mensaje",
    "key": "MiClaveSecreta16",
    "mode": "CBC|ECB|CTR"
}
```

**Ejemplo - Cifrar CBC:**
```json
// Request
{
    "action": "encrypt",
    "text": "Datos confidenciales",
    "key": "MiClaveSecreta16",
    "mode": "CBC"
}

// Response
{
    "success": true,
    "mode": "CBC",
    "result": {
        "ciphertext": "U2FsdGVkX1+...",
        "ciphertext_hex": "a1b2c3d4e5f6...",
        "iv": "randomIVbase64==",
        "iv_hex": "1234567890abcdef",
        "mode": "CBC",
        "key_size": 128
    }
}
```

**Ejemplo - Info Técnica:**
```json
// Response
{
    "result": {
        "name": "AES - Advanced Encryption Standard",
        "type": "Cifrado de bloque simétrico",
        "block_size": "128 bits",
        "key_sizes": ["128 bits (10 rondas)", "192 bits (12 rondas)", "256 bits (14 rondas)"],
        "operations": {
            "SubBytes": "Sustitución no lineal usando S-Box de 256 bytes",
            "ShiftRows": "Permutación cíclica de las filas del estado",
            "MixColumns": "Mezcla de columnas en el campo GF(2^8)",
            "AddRoundKey": "XOR del estado con la subclave de la ronda"
        }
    }
}
```

---

#### POST `/api/custom-symmetric/`

**Descripción:** Algoritmo simétrico propio (CipherX)

**Request Body:**
```json
{
    "action": "encrypt|decrypt|info|visualize",
    "text": "Mensaje",
    "key": "ClaveXYZ"
}
```

**Ejemplo - Cifrar:**
```json
// Request
{"action": "encrypt", "text": "Mensaje secreto", "key": "ClaveXYZ"}

// Response
{
    "success": true,
    "result": "a1b2c3d4e5f6789012345678"
}
```

**Ejemplo - Visualizar Ronda:**
```json
// Response
{
    "result": {
        "input": "4d656e73616a6520",
        "after_key_xor": "1a2b3c4d5e6f7080",
        "after_sbox": "6a4c5d2e3f4a5b6c",
        "after_pbox": "2c3d4e5f6a7b8c9d"
    }
}
```

---

#### POST `/api/custom-asymmetric/`

**Descripción:** Algoritmo asimétrico propio (SimpleRSA)

**Request Body:**
```json
{
    "action": "generate|encrypt|decrypt|sign|verify|visualize|info",
    "text": "Mensaje"
}
```

**Ejemplo - Generar Claves:**
```json
// Response
{
    "result": {
        "p": 101,
        "q": 103,
        "n": 10403,
        "phi_n": 10200,
        "e": 17,
        "d": 5993,
        "public_key": "(17, 10403)",
        "private_key": "(5993, 10403)",
        "bit_length": 14
    }
}
```

**Ejemplo - Visualizar Cifrado:**
```json
// Request
{"action": "visualize", "text": "H"}

// Response
{
    "result": {
        "character": "H",
        "ascii_value": 72,
        "public_key": "(e=17, n=10403)",
        "formula": "c = m^e mod n = 72^17 mod 10403",
        "ciphertext": 8765,
        "decryption_formula": "m = c^d mod n = 8765^5993 mod 10403",
        "decrypted_value": 72,
        "recovered_char": "H"
    }
}
```

---

### 3.2 Endpoints de Autenticación

#### POST `/api/hmac/`

**Descripción:** Operaciones HMAC

**Request Body:**
```json
{
    "action": "create|verify|authenticate|verify_full|explain",
    "message": "Mensaje",
    "key": "clave_secreta",
    "mac": "hash_recibido"
}
```

**Ejemplo - Crear MAC:**
```json
// Request
{"action": "create", "message": "Transferir $1000", "key": "secreto123"}

// Response
{
    "result": {
        "message": "Transferir $1000",
        "mac": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
        "algorithm": "SHA-256"
    }
}
```

**Ejemplo - Verificar:**
```json
// Request
{
    "action": "verify",
    "message": "Transferir $1000",
    "key": "secreto123",
    "mac": "a1b2c3d4..."
}

// Response
{
    "result": {
        "is_valid": true,
        "message": "Transferir $1000"
    }
}
```

---

#### POST `/api/signature/`

**Descripción:** Firmas digitales RSA

**Request Body:**
```json
{
    "action": "sign|verify|explain",
    "message": "Documento"
}
```

**Ejemplo - Firmar:**
```json
// Response
{
    "result": {
        "message": "Documento legal",
        "signature": "a1b2c3d4e5f6...(hex)",
        "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBI...",
        "timestamp": "2024-12-19T10:30:00",
        "algorithm": "RSA-SHA256"
    }
}
```

---

#### POST `/api/origin-verification/`

**Descripción:** Simulación de verificación de origen

**Request Body:**
```json
{
    "action": "simulate|compare"
}
```

**Ejemplo - Simular Canal Seguro:**
```json
// Response
{
    "result": {
        "scenario": "Alice envía un mensaje secreto a Bob",
        "steps": [
            {
                "step": 1,
                "action": "Establecer clave compartida",
                "description": "Alice y Bob acuerdan una clave secreta"
            },
            {
                "step": 2,
                "action": "Alice crea mensaje autenticado",
                "message": "Transferir $1000 a cuenta 12345",
                "mac": "7f8a9b..."
            },
            {
                "step": 3,
                "action": "Bob verifica el mensaje",
                "is_authentic": true
            },
            {
                "step": 4,
                "action": "Simulación de ataque",
                "tampered_message": "Transferir $10000",
                "detection": "DETECTADO"
            }
        ]
    }
}
```

---

### 3.3 Endpoints de Ataques

#### POST `/api/brute-force/`

**Descripción:** Simulación de ataques de fuerza bruta

**Request Body:**
```json
{
    "action": "caesar|estimate|frequency|info",
    "ciphertext": "Texto cifrado",
    "key_length": 8,
    "charset_size": 62
}
```

**Ejemplo - Estimar Tiempo:**
```json
// Request
{"action": "estimate", "key_length": 8, "charset_size": 62}

// Response
{
    "result": {
        "key_length": 8,
        "charset_size": 62,
        "total_combinations": "218,340,105,584,896",
        "attempts_per_second": "1,000,000",
        "time_estimate": {
            "years": 6.92
        },
        "conclusion": "⚡ MODERADO - Ataque posible con recursos"
    }
}
```

---

#### POST `/api/mitm/`

**Descripción:** Simulación de ataques Man-in-the-Middle

**Request Body:**
```json
{
    "scenario": "unencrypted|diffie_hellman|with_signature|info"
}
```

**Ejemplo - Escenario DH:**
```json
// Response
{
    "result": {
        "scenario": "Ataque MITM en Diffie-Hellman",
        "result": "ATAQUE EXITOSO",
        "steps": [
            {"step": 1, "action": "Alice genera clave pública", "alice_public": 8},
            {"step": 2, "action": "Eve intercepta", "eve_sends_to_bob": 15},
            {"step": 3, "action": "Bob genera clave pública", "bob_public": 19},
            {"step": 4, "action": "Eve intercepta", "eve_sends_to_alice": 7},
            {"step": 5, "action": "Secretos calculados", "problem": "Alice y Bob tienen secretos diferentes"}
        ],
        "conclusion": "Sin autenticación, DH es vulnerable a MITM",
        "solution": "Usar certificados digitales"
    }
}
```

---

## 4. Módulos de Backend

### 4.1 caesar.py - Cifrado César

**Clase:** `CaesarCipher`

| Método | Parámetros | Retorno | Descripción |
|--------|------------|---------|-------------|
| `__init__` | `shift: int = 3` | - | Inicializa con desplazamiento |
| `encrypt` | `plaintext: str` | `str` | Cifra el mensaje |
| `decrypt` | `ciphertext: str` | `str` | Descifra el mensaje |
| `brute_force_decrypt` | `ciphertext: str` | `list[tuple]` | Prueba 26 desplazamientos |
| `frequency_analysis` | `text: str` | `dict` | Análisis de frecuencias |

**Ejemplo de Uso:**
```python
from crypto_app.algorithms import CaesarCipher

cipher = CaesarCipher(shift=3)
encrypted = cipher.encrypt("Hola Mundo")  # "Krod Pxqgr"
decrypted = cipher.decrypt("Krod Pxqgr")  # "Hola Mundo"

# Fuerza bruta
results = cipher.brute_force_decrypt("Krod Pxqgr")
# [(0, "Krod Pxqgr"), (1, "Jqnc Owpf..."), (3, "Hola Mundo"), ...]
```

---

### 4.2 lfsr.py - Linear Feedback Shift Register

**Clases:** `LFSR`, `LFSRCipher`

| Método | Descripción |
|--------|-------------|
| `LFSR.step()` | Ejecuta un paso del registro |
| `LFSR.generate_keystream(length)` | Genera secuencia de bits |
| `LFSRCipher.encrypt(text)` | Cifra con XOR |
| `LFSRCipher.decrypt(hex)` | Descifra |
| `LFSRCipher.visualize_process(text)` | Muestra cada paso |

**Ejemplo:**
```python
from crypto_app.algorithms import LFSRCipher

cipher = LFSRCipher(seed=0xACE1)
ciphertext, keystream = cipher.encrypt("Secreto")
plaintext = cipher.decrypt(ciphertext)
```

---

### 4.3 aes_demo.py - AES

**Clase:** `AESDemo`

| Método | Descripción |
|--------|-------------|
| `encrypt(plaintext)` | Cifra con modo configurado |
| `decrypt(ciphertext, iv, nonce)` | Descifra |
| `explain_subbytes(byte)` | Explica sustitución S-Box |
| `explain_shiftrows(state)` | Explica permutación de filas |
| `get_algorithm_info()` | Información técnica completa |

**Ejemplo:**
```python
from crypto_app.algorithms import AESDemo

aes = AESDemo(key=b'MiClaveSecreta16', mode='CBC')
result = aes.encrypt("Mensaje secreto")
# {
#     'ciphertext': 'base64...',
#     'iv': 'base64...',
#     'mode': 'CBC',
#     'key_size': 128
# }
```

---

### 4.4 custom_symmetric.py - CipherX

**Clase:** `CipherX`

**Componentes internos:**
- `S_BOX`: Tabla de sustitución 4→4 bits (16 entradas)
- `S_BOX_INV`: Inversa para descifrado
- `P_BOX`: Permutación de 64 bits
- `_generate_subkeys()`: Rotación + XOR con constante de ronda

| Método | Descripción |
|--------|-------------|
| `encrypt(plaintext)` | Cifra (hex output) |
| `decrypt(ciphertext_hex)` | Descifra |
| `visualize_round(block, round_num)` | Muestra transformaciones |

**Estructura de una ronda:**
```
1. XOR con subclave
2. Sustitución (S-Box por nibbles)
3. Permutación (P-Box 64 bits)
```

---

### 4.5 custom_asymmetric.py - SimpleRSA

**Clase:** `SimpleRSA`

| Método | Descripción |
|--------|-------------|
| `generate_keys()` | Genera par p, q, n, e, d |
| `get_public_key()` | Retorna (e, n) |
| `get_private_key()` | Retorna (d, n) |
| `encrypt(text)` | Cifra carácter por carácter |
| `decrypt(ciphertext)` | Descifra lista de números |
| `sign(message)` | Firma con clave privada |
| `verify(message, signature)` | Verifica firma |
| `visualize_encryption(char)` | Muestra proceso completo |

---

### 4.6 message_auth.py - Autenticación

**Clases:** `HMACAuthenticator`, `DigitalSignature`, `MessageOriginVerifier`

**HMACAuthenticator:**
```python
auth = HMACAuthenticator("clave_secreta")
mac = auth.create_mac("mensaje")
is_valid = auth.verify_mac("mensaje", mac)
authenticated_msg = auth.create_authenticated_message("mensaje")
```

**DigitalSignature:**
```python
signer = DigitalSignature(key_size=2048)
signature = signer.sign("documento")
is_valid = signer.verify("documento", signature)
signed_msg = signer.create_signed_message("documento")
```

---

### 4.7 brute_force.py - Ataques

**Clases:** `BruteForceAttack`, `FrequencyAnalysis`

| Método | Descripción |
|--------|-------------|
| `attack_caesar(ciphertext)` | Fuerza bruta contra César |
| `dictionary_attack(ciphertext, decrypt_func, wordlist)` | Ataque de diccionario |
| `estimate_brute_force_time(key_length, charset_size)` | Estima tiempo de ataque |
| `FrequencyAnalysis.analyze(text)` | Análisis de frecuencias |
| `FrequencyAnalysis.break_substitution(ciphertext)` | Intenta romper sustitución |

---

### 4.8 mitm_demo.py - Man-in-the-Middle

**Clases:** `Party`, `MITMAttacker`, `MITMSimulation`

**Escenarios:**
1. `scenario_unencrypted()` - Sin protección
2. `scenario_diffie_hellman_attack()` - DH sin autenticar
3. `scenario_with_signature()` - Con firma digital

---

## 5. Frontend (JavaScript)

### 5.1 Funciones de API

```javascript
// Función genérica para llamadas API
async function apiCall(endpoint, data) {
    const response = await fetch(endpoint, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
    });
    return await response.json();
}

// Mostrar resultados
function showOutput(elementId, content, isError = false) {
    const element = document.getElementById(elementId);
    element.textContent = typeof content === 'object' 
        ? JSON.stringify(content, null, 2) 
        : content;
    element.className = 'output ' + (isError ? 'error' : 'success');
}
```

### 5.2 Funciones por Página

**index.html:**
- `demoCaesar(action)` - Demo rápida de César

**algorithms.html:**
- `caesar(action)` - Cifrado César
- `lfsr(action)` - LFSR
- `aes(action)` - AES
- `customSymmetric(action)` - CipherX
- `customAsymmetric(action)` - SimpleRSA

**authentication.html:**
- `hmac(action)` - HMAC
- `signature(action)` - Firma digital
- `simulateChannel()` - Canal seguro
- `createMAC()` / `verifyMAC()` - Demo de integridad

**attacks.html:**
- `bruteForce(action)` - Ataques de fuerza bruta
- `runMITM()` - Simulación MITM

---

## 6. Diseño de Interfaz

### 6.1 Variables CSS

```css
:root {
    --primary: #6366f1;      /* Indigo */
    --secondary: #10b981;    /* Emerald */
    --accent: #f59e0b;       /* Amber */
    --danger: #ef4444;       /* Red */
    --bg-dark: #0f172a;      /* Slate 900 */
    --bg-card: #1e293b;      /* Slate 800 */
    --text-primary: #f1f5f9; /* Slate 100 */
    --gradient: linear-gradient(135deg, #6366f1, #8b5cf6, #a855f7);
}
```

### 6.2 Componentes

| Componente | Clase CSS | Uso |
|------------|-----------|-----|
| Card | `.card` | Contenedores principales |
| Button Primary | `.btn-primary` | Acciones principales |
| Button Danger | `.btn-danger` | Ataques/acciones destructivas |
| Output | `.output` | Resultados de operaciones |
| Info Box | `.info-box` | Información educativa |
| Warning Box | `.warning-box` | Advertencias |
| Badge | `.badge-*` | Etiquetas de estado |

---

## 7. Ejecución del Sistema

### 7.1 Instalación

```bash
# Clonar/navegar al proyecto
cd C:\Users\JEanpa\.gemini\antigravity\scratch\crypto_security

# Instalar dependencias
pip install django pycryptodome

# Migraciones
python manage.py migrate

# Ejecutar servidor
python manage.py runserver 8000
```

### 7.2 URLs Disponibles

| URL | Descripción |
|-----|-------------|
| http://127.0.0.1:8000/ | Dashboard principal |
| http://127.0.0.1:8000/algorithms/ | Algoritmos de cifrado |
| http://127.0.0.1:8000/authentication/ | Autenticación de mensajes |
| http://127.0.0.1:8000/attacks/ | Simulación de ataques |
| http://127.0.0.1:8000/admin/ | Panel de administración |

---

## 8. Resumen de Funcionalidades

| Categoría | Funcionalidad | Estado |
|-----------|---------------|--------|
| **Algoritmos** | Cifrado César | ✅ |
| | LFSR (Acarreo) | ✅ |
| | AES (CBC/ECB/CTR) | ✅ |
| | CipherX (Simétrico propio) | ✅ |
| | SimpleRSA (Asimétrico propio) | ✅ |
| **Autenticación** | HMAC | ✅ |
| | Firma Digital RSA | ✅ |
| | Verificación de Origen | ✅ |
| **Ataques** | Fuerza Bruta César | ✅ |
| | Estimador de Tiempo | ✅ |
| | Análisis de Frecuencia | ✅ |
| | MITM (3 escenarios) | ✅ |
| **Interfaz** | Dashboard | ✅ |
| | 4 páginas HTML | ✅ |
| | API REST (11 endpoints) | ✅ |
| | Diseño responsivo | ✅ |
