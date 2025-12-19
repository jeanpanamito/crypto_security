# Informe Técnico: Sistema de Criptografía y Seguridad de la Información

## 1. Introducción

Este documento presenta un sistema educativo desarrollado en Django que demuestra los principales conceptos de criptografía y seguridad de la información, incluyendo algoritmos de cifrado, verificación de mensajes y simulación de ataques.

---

## 2. Autenticación: Verificación del Origen de un Mensaje

### 2.1 Problema
¿Cómo podemos estar seguros de que un mensaje:
- Proviene de quien dice ser el remitente?
- No ha sido alterado en tránsito?

### 2.2 Solución: HMAC (Hash-based Message Authentication Code)

```python
import hmac
import hashlib

def create_mac(message: str, secret_key: str) -> str:
    """Crea un código de autenticación para un mensaje."""
    return hmac.new(
        secret_key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()

def verify_mac(message: str, mac: str, secret_key: str) -> bool:
    """Verifica si el MAC es válido para el mensaje."""
    expected = create_mac(message, secret_key)
    return hmac.compare_digest(expected, mac)
```

**Funcionamiento:**
1. El remitente y destinatario comparten una clave secreta
2. El remitente calcula `HMAC(clave, mensaje)` y lo envía junto al mensaje
3. El destinatario recalcula el HMAC con su clave
4. Si coinciden, el mensaje es auténtico e íntegro

### 2.3 Solución Alternativa: Firma Digital

Para escenarios donde no se puede compartir una clave secreta:

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Generar par de claves
key = RSA.generate(2048)
public_key = key.publickey()

# Firmar
def sign(message: str) -> bytes:
    h = SHA256.new(message.encode())
    return pkcs1_15.new(key).sign(h)

# Verificar
def verify(message: str, signature: bytes, pub_key) -> bool:
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except:
        return False
```

---

## 3. Funcionamiento de AES (Advanced Encryption Standard)

### 3.1 Características Técnicas

| Propiedad | Valor |
|-----------|-------|
| Tipo | Cifrado de bloque simétrico |
| Tamaño de bloque | 128 bits |
| Tamaños de clave | 128, 192, 256 bits |
| Estructura | Red de Sustitución-Permutación (SPN) |
| Rondas | 10 (128-bit), 12 (192-bit), 14 (256-bit) |

### 3.2 Operaciones por Ronda

1. **SubBytes** - Sustitución no lineal usando S-Box
   ```
   Cada byte se reemplaza consultando una tabla de 256 entradas
   S-Box[byte] → byte_sustituido
   ```

2. **ShiftRows** - Permutación de filas
   ```
   Fila 0: sin cambios
   Fila 1: rotar 1 posición izquierda
   Fila 2: rotar 2 posiciones izquierda
   Fila 3: rotar 3 posiciones izquierda
   ```

3. **MixColumns** - Mezcla de columnas en GF(2^8)
   ```
   Cada columna se multiplica por una matriz fija en el campo de Galois
   ```

4. **AddRoundKey** - XOR con subclave de la ronda
   ```
   Estado ⊕ Subclave_i
   ```

### 3.3 Implementación en Python

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)  # AES-256
iv = get_random_bytes(16)

# Cifrar
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(b"mensaje", 16))

# Descifrar
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(ciphertext), 16)
```

---

## 4. Algoritmos Propios

### 4.1 Algoritmo Simétrico: CipherX

**Estructura:**
- Tamaño de bloque: 64 bits
- Tamaño de clave: 64 bits
- Rondas: 4

**Componentes:**
- **S-Box 4x4**: Sustitución no lineal de nibbles
- **P-Box**: Permutación de 64 bits
- **Key Schedule**: Rotación + XOR con constante de ronda

```python
# Ejemplo de S-Box
S_BOX = [0x6, 0x4, 0xC, 0x5, 0x0, 0x7, 0x2, 0xE,
         0x1, 0xF, 0x3, 0xD, 0x8, 0xA, 0x9, 0xB]

def apply_sbox(value: int) -> int:
    result = 0
    for i in range(16):  # 16 nibbles
        nibble = (value >> (i * 4)) & 0xF
        result |= S_BOX[nibble] << (i * 4)
    return result
```

### 4.2 Algoritmo Asimétrico: SimpleRSA

**Fundamentos matemáticos:**
```
n = p × q           (producto de dos primos)
φ(n) = (p-1)(q-1)   (función de Euler)
e × d ≡ 1 (mod φ(n)) (inverso modular)

Cifrado:   c = m^e mod n
Descifrado: m = c^d mod n
```

**Implementación:**
```python
class SimpleRSA:
    def __init__(self):
        self.p = 101  # primo 1
        self.q = 103  # primo 2
        self.n = self.p * self.q  # 10403
        self.phi_n = (self.p - 1) * (self.q - 1)  # 10200
        self.e = 17  # exponente público
        self.d = self._mod_inverse(self.e, self.phi_n)  # exponente privado
    
    def encrypt(self, m: int) -> int:
        return pow(m, self.e, self.n)
    
    def decrypt(self, c: int) -> int:
        return pow(c, self.d, self.n)
```

---

## 5. Algoritmos Clásicos

### 5.1 Cifrado César

```
Cifrado:   C = (P + K) mod 26
Descifrado: P = (C - K) mod 26
```

**Seguridad:** Muy débil (solo 26 claves posibles)

### 5.2 Algoritmo por Acarreo (LFSR)

Linear Feedback Shift Register genera una secuencia pseudoaleatoria:

```
Estado: [1,0,1,1,0,0,1,0]
Taps:   [7, 5, 4, 3]
Nuevo bit = bit[7] ⊕ bit[5] ⊕ bit[4] ⊕ bit[3]
```

El keystream se combina con XOR con el texto plano.

---

## 6. Comparativa de Algoritmos del Mercado

| Algoritmo | Tipo | Tamaño Clave | Seguridad | Velocidad | Uso |
|-----------|------|--------------|-----------|-----------|-----|
| **DES** | Bloque | 56 bits | ❌ Obsoleto | Rápido | Legado |
| **3DES** | Bloque | 168 bits | ⚠️ Débil | Lento | Legado bancario |
| **AES** | Bloque | 128-256 bits | ✅ Seguro | Muy rápido | Estándar actual |
| **ChaCha20** | Flujo | 256 bits | ✅ Seguro | Muy rápido | TLS 1.3, móviles |
| **RSA** | Asimétrico | 2048+ bits | ✅ Seguro | Lento | Intercambio claves |
| **ECC** | Asimétrico | 256+ bits | ✅ Muy seguro | Rápido | Móviles, IoT |

### Ventajas y Desventajas

**AES:**
- ✅ Estándar mundial, muy auditado
- ✅ Aceleración en hardware (AES-NI)
- ❌ Vulnerable a ataques de canal lateral si mal implementado

**RSA:**
- ✅ Bien entendido matemáticamente
- ✅ Proporciona no repudio
- ❌ Claves grandes, operaciones lentas

**ChaCha20:**
- ✅ Excelente en software sin hardware especializado
- ✅ Resistente a ataques de timing
- ❌ Menos maduro que AES

---

## 7. Ataques Comunes

### 7.1 Ataque de Fuerza Bruta

**Concepto:** Probar todas las claves posibles hasta encontrar la correcta.

**Estimación de tiempo (1,000,000 intentos/segundo):**

| Longitud | Charset | Combinaciones | Tiempo |
|----------|---------|---------------|--------|
| 4 chars | a-z | 456,976 | < 1 segundo |
| 8 chars | a-z, A-Z, 0-9 | 218 billones | 7 años |
| 16 chars | Todo imprimible | 10^31 | Trillones de años |

**Defensa:**
- Claves largas (16+ caracteres)
- Límite de intentos (rate limiting)
- Funciones de derivación lentas (bcrypt, Argon2)

### 7.2 Ataque Man-in-the-Middle (MITM)

**Concepto:** El atacante intercepta la comunicación entre dos partes.

**Escenarios:**
1. **Sin cifrado:** Eve lee y modifica todo
2. **DH sin autenticación:** Eve intercambia claves con ambas partes
3. **Con firma digital:** Eve detectada al no poder falsificar firmas

**Herramientas Kali Linux:**
- `ettercap` - Framework MITM
- `bettercap` - Herramienta modular
- `wireshark` - Análisis de tráfico
- `arpspoof` - Envenenamiento ARP

**Defensa:**
- HTTPS con certificados válidos
- Certificate pinning
- VPN en redes no confiables
- HSTS headers

### 7.3 Cómo Descifrar Algo

1. **Identificar el cifrado:** Base64? Hex? César?
2. **Análisis de frecuencia:** Patrones en el texto
3. **Conocer contexto:** Idioma, formato esperado
4. **Probar ataques conocidos:** Fuerza bruta si viable
5. **Buscar debilidades:** IVs repetidos, claves débiles

**Herramientas útiles:**
- CyberChef
- dCode
- hash-identifier
- CrackStation

---

## 8. Herramientas de Kali Linux

### 8.1 Cracking de Contraseñas

```bash
# Hashcat - GPU
hashcat -m 0 -a 0 hash.txt wordlist.txt

# John the Ripper
john --wordlist=rockyou.txt hashes.txt

# Hydra - Online
hydra -l admin -P passwords.txt ssh://target
```

### 8.2 Análisis de Red

```bash
# Wireshark - GUI
wireshark

# tcpdump - CLI
tcpdump -i eth0 -w capture.pcap

# Ettercap
ettercap -T -M arp:remote /target1/ /target2/
```

### 8.3 MITM

```bash
# ARP Spoofing
arpspoof -i eth0 -t victim gateway

# SSL Strip
sslstrip -l 8080
```

---

## 9. Conclusiones

1. **La seguridad es multicapa:** No depender de un solo mecanismo
2. **Usar estándares probados:** AES, RSA, SHA-256
3. **Nunca rodar tu propia criptografía** en producción
4. **La verificación de origen es esencial:** HMAC o firmas digitales
5. **Los ataques evolucionan:** Mantener sistemas actualizados

---

## 10. Referencias

- NIST FIPS 197 (AES)
- RFC 2104 (HMAC)
- RFC 8017 (PKCS #1: RSA)
- Practical Cryptography, Ferguson & Schneier
- Applied Cryptography, Bruce Schneier
