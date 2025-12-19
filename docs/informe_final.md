# Informe Final: Criptografía y Seguridad de la Información

**Materia:** Seguridad de la Información  
**Tema:** Sistema de Demostración Criptográfica  
**Tecnología:** Django + Python  

---

## Tabla de Contenidos

1. [Autenticación: Verificar el Origen de un Mensaje](#1-autenticación-verificar-el-origen-de-un-mensaje)
2. [Funcionamiento de AES](#2-funcionamiento-de-aes)
3. [Algoritmo Propio](#3-algoritmo-propio)
4. [Algoritmo por Acarreo (LFSR)](#4-algoritmo-por-acarreo-lfsr)
5. [Algoritmo César](#5-algoritmo-césar)
6. [Otros Algoritmos en el Mercado](#6-otros-algoritmos-en-el-mercado)
7. [Ataques más Comunes](#7-ataques-más-comunes)

---

## Capturas del Sistema

### Vista Principal (Dashboard)

![Captura del Dashboard - Vista principal del sistema con acceso a todos los módulos](screenshots/dashboard.png)

*Figura 1: Dashboard principal del sistema mostrando las tres secciones principales: Algoritmos, Autenticación y Ataques.*

---

## 1. Autenticación: Verificar el Origen de un Mensaje

### 1.1 El Problema

Cuando recibimos un mensaje digital, enfrentamos dos preguntas fundamentales:
- **¿Quién lo envió realmente?** (Autenticidad)
- **¿Ha sido modificado en el camino?** (Integridad)

Sin mecanismos de autenticación, un atacante podría:
- Suplantar la identidad del remitente
- Modificar el contenido del mensaje
- Negar haber enviado un mensaje (repudio)

### 1.2 Solución 1: HMAC (Hash-based Message Authentication Code)

#### ¿Cómo funciona?

HMAC combina una función hash con una clave secreta compartida:

```
HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))

Donde:
- K = clave secreta
- m = mensaje
- H = función hash (SHA-256)
- opad = 0x5c repetido
- ipad = 0x36 repetido
- || = concatenación
- ⊕ = XOR
```

#### Implementación en Python

```python
import hmac
import hashlib

class HMACAuthenticator:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode('utf-8')
    
    def create_mac(self, message: str) -> str:
        """Crea un código de autenticación para el mensaje."""
        h = hmac.new(self.secret_key, message.encode('utf-8'), hashlib.sha256)
        return h.hexdigest()
    
    def verify_mac(self, message: str, mac: str) -> bool:
        """Verifica si el MAC es válido."""
        expected_mac = self.create_mac(message)
        return hmac.compare_digest(expected_mac, mac)

# Ejemplo de uso
auth = HMACAuthenticator("clave_secreta_compartida")
mensaje = "Transferir $1000 a cuenta 12345"
mac = auth.create_mac(mensaje)
```

#### Captura: Interfaz HMAC

![Captura de la interfaz HMAC - Creación y verificación de códigos de autenticación](screenshots/hmac_interface.png)

*Figura 2: Interfaz para crear y verificar códigos HMAC. Se muestra el formulario con mensaje, clave secreta y el MAC generado.*

---

#### Flujo de Comunicación

```
┌─────────┐                                          ┌─────────┐
│  ALICE  │                                          │   BOB   │
└────┬────┘                                          └────┬────┘
     │                                                    │
     │ 1. Tiene clave secreta "K"                        │
     │                                                    │ Tiene clave "K"
     │ 2. Calcula MAC = HMAC(K, mensaje)                 │
     │                                                    │
     │ 3. Envía: {mensaje, MAC}                          │
     │ ──────────────────────────────────────────────────►│
     │                                                    │
     │                    4. Recalcula MAC' = HMAC(K, mensaje)
     │                                                    │
     │                    5. ¿MAC == MAC'?                │
     │                       Sí → Mensaje auténtico       │
     │                       No → RECHAZADO               │
```

### 1.3 Solución 2: Firma Digital (RSA)

Para escenarios donde **no se puede compartir una clave secreta previamente**.

#### ¿Cómo funciona?

```
1. El remitente genera par de claves: (pública, privada)
2. Calcula hash del mensaje: h = SHA256(mensaje)
3. Firma el hash con clave privada: firma = h^d mod n
4. Envía: mensaje + firma + clave pública
5. El destinatario verifica: h' == firma^e mod n
```

#### Implementación

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class DigitalSignature:
    def __init__(self, key_size: int = 2048):
        self.key = RSA.generate(key_size)
        self.public_key = self.key.publickey()
    
    def sign(self, message: str) -> bytes:
        """Firma un mensaje con la clave privada."""
        h = SHA256.new(message.encode('utf-8'))
        signature = pkcs1_15.new(self.key).sign(h)
        return signature
    
    def verify(self, message: str, signature: bytes) -> bool:
        """Verifica una firma con la clave pública."""
        h = SHA256.new(message.encode('utf-8'))
        try:
            pkcs1_15.new(self.public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
```

#### Captura: Interfaz Firma Digital

![Captura de la interfaz de Firma Digital - Firmar y verificar documentos](screenshots/firma_digital.png)

*Figura 3: Interfaz de firma digital mostrando el proceso de firmar un documento y la generación de la firma RSA-SHA256.*

---

### 1.4 Captura: Verificación de Integridad

![Captura de Demo de Verificación - Detección de alteraciones en mensajes](screenshots/verificacion_integridad.png)

*Figura 4: Demostración de verificación de integridad. Se muestra cómo el sistema detecta cuando un mensaje ha sido alterado.*

---

### 1.5 Comparativa HMAC vs Firma Digital

| Característica | HMAC | Firma Digital |
|----------------|------|---------------|
| **Tipo** | Simétrico | Asimétrico |
| **Clave compartida** | ✅ Requiere | ❌ No requiere |
| **No repudio** | ❌ No | ✅ Sí |
| **Velocidad** | ⚡ Muy rápida | 🐢 Más lenta |
| **Quién verifica** | Solo quien tiene la clave | Cualquiera |
| **Uso típico** | APIs, sesiones, tokens | Certificados, contratos |

---

## 2. Funcionamiento de AES

### 2.1 ¿Qué es AES?

**Advanced Encryption Standard (AES)** es el estándar de cifrado simétrico adoptado por NIST en 2001 para reemplazar a DES. Es el algoritmo más utilizado actualmente para proteger datos.

### 2.2 Características Técnicas

| Propiedad | Valor |
|-----------|-------|
| Tipo | Cifrado de bloque simétrico |
| Tamaño de bloque | 128 bits (16 bytes) |
| Tamaños de clave | 128, 192, 256 bits |
| Rondas | 10 (128-bit), 12 (192-bit), 14 (256-bit) |
| Estructura | Red de Sustitución-Permutación (SPN) |

### 2.3 Estructura Interna

AES opera sobre una **matriz de estado** de 4×4 bytes:

```
Estado inicial (128 bits = 16 bytes):
┌────┬────┬────┬────┐
│ S0 │ S4 │ S8 │ S12│
├────┼────┼────┼────┤
│ S1 │ S5 │ S9 │ S13│
├────┼────┼────┼────┤
│ S2 │ S6 │ S10│ S14│
├────┼────┼────┼────┤
│ S3 │ S7 │ S11│ S15│
└────┴────┴────┴────┘
```

### 2.4 Las 4 Operaciones de Cada Ronda

#### 1. SubBytes (Sustitución)

Cada byte se reemplaza usando una **S-Box** de 256 entradas.

**¿Por qué?** Proporciona **no linealidad**, esencial para resistir criptoanálisis.

#### 2. ShiftRows (Permutación de filas)

```
Antes:                    Después:
┌────┬────┬────┬────┐     ┌────┬────┬────┬────┐
│ A0 │ A1 │ A2 │ A3 │     │ A0 │ A1 │ A2 │ A3 │  ← Sin cambio
├────┼────┼────┼────┤     ├────┼────┼────┼────┤
│ B0 │ B1 │ B2 │ B3 │     │ B1 │ B2 │ B3 │ B0 │  ← Rotar 1 izq
├────┼────┼────┼────┤     ├────┼────┼────┼────┤
│ C0 │ C1 │ C2 │ C3 │     │ C2 │ C3 │ C0 │ C1 │  ← Rotar 2 izq
├────┼────┼────┼────┤     ├────┼────┼────┼────┤
│ D0 │ D1 │ D2 │ D3 │     │ D3 │ D0 │ D1 │ D2 │  ← Rotar 3 izq
└────┴────┴────┴────┘     └────┴────┴────┴────┘
```

#### 3. MixColumns (Mezcla de columnas)

Cada columna se multiplica por una matriz fija en el campo de Galois GF(2^8).

#### 4. AddRoundKey (Mezcla con clave)

XOR del estado con la subclave de la ronda.

### 2.5 Modos de Operación

- **ECB**: Inseguro - bloques iguales producen cifrados iguales
- **CBC**: Cada bloque depende del anterior
- **CTR**: Paralelizable, usado en TLS 1.3

### Captura: Interfaz AES

![Captura de la interfaz AES - Cifrado con diferentes modos](screenshots/aes_interface.png)

*Figura 5: Interfaz de cifrado AES mostrando los campos de mensaje, clave, selección de modo (CBC/ECB/CTR) y el resultado cifrado.*

---

### Captura: Información Técnica AES

![Captura de información técnica AES - Explicación de operaciones](screenshots/aes_info.png)

*Figura 6: Información técnica de AES mostrando detalles sobre las operaciones SubBytes, ShiftRows, MixColumns y AddRoundKey.*

---

## 3. Algoritmo Propio

### 3.1 Algoritmo Simétrico: CipherX

#### Especificaciones

| Propiedad | Valor |
|-----------|-------|
| Nombre | CipherX |
| Tipo | Cifrado de bloque simétrico |
| Tamaño de bloque | 64 bits |
| Tamaño de clave | 64 bits |
| Rondas | 4 |
| Estructura | Red de Sustitución-Permutación |

#### Componentes

**S-Box (4 bits → 4 bits):**
```python
S_BOX = [0x6, 0x4, 0xC, 0x5, 0x0, 0x7, 0x2, 0xE,
         0x1, 0xF, 0x3, 0xD, 0x8, 0xA, 0x9, 0xB]
```

#### Flujo de una Ronda

```
        Entrada (64 bits)
              │
              ▼
    ┌─────────────────────┐
    │  XOR con Subclave   │
    └─────────────────────┘
              │
              ▼
    ┌─────────────────────┐
    │     S-Box (16x)     │  ← 16 nibbles de 4 bits
    └─────────────────────┘
              │
              ▼
    ┌─────────────────────┐
    │   P-Box (64 bits)   │
    └─────────────────────┘
              │
              ▼
         Salida (64 bits)
```

### Captura: Interfaz CipherX

![Captura de la interfaz CipherX - Algoritmo simétrico propio](screenshots/cipherx_interface.png)

*Figura 7: Interfaz del algoritmo CipherX mostrando el cifrado de un mensaje con la clave de 8 caracteres.*

---

### 3.2 Algoritmo Asimétrico: SimpleRSA

#### Fundamentos Matemáticos

```
1. Elegir dos primos grandes: p, q
2. Calcular n = p × q
3. Calcular φ(n) = (p-1)(q-1)  [Función de Euler]
4. Elegir e: 1 < e < φ(n), gcd(e, φ(n)) = 1
5. Calcular d: e × d ≡ 1 (mod φ(n))  [Inverso modular]

Clave pública:  (e, n)
Clave privada: (d, n)

Cifrado:   c = m^e mod n
Descifrado: m = c^d mod n
```

#### Ejemplo Numérico Paso a Paso

```
Datos:
  p = 101, q = 103
  n = 101 × 103 = 10403
  φ(n) = 100 × 102 = 10200
  e = 17
  d = 5993 (porque 17 × 5993 = 101881 ≡ 1 mod 10200)

Cifrar 'H' (ASCII 72):
  c = 72^17 mod 10403 = 5765

Descifrar 5765:
  m = 5765^5993 mod 10403 = 72
  chr(72) = 'H'
```

### Captura: Generación de Claves RSA

![Captura de generación de claves SimpleRSA - Muestra p, q, n, φ(n), e, d](screenshots/simplersa_keygen.png)

*Figura 8: Generación de claves RSA mostrando los valores de p, q, n, φ(n), exponente público (e) y exponente privado (d).*

---

### Captura: Visualización de Cifrado RSA

![Captura de visualización RSA - Proceso paso a paso](screenshots/simplersa_visualize.png)

*Figura 9: Visualización del proceso de cifrado RSA mostrando la fórmula aplicada a cada carácter.*

---

## 4. Algoritmo por Acarreo (LFSR)

### 4.1 ¿Qué es un LFSR?

**Linear Feedback Shift Register (LFSR)** es un registro de desplazamiento cuyo bit de entrada es una función lineal (XOR) de su estado anterior.

### 4.2 Funcionamiento Técnico

```
Registro de 8 bits con taps en posiciones 7, 5, 4, 3:

Estado inicial: [1,0,1,1,0,0,1,0]
                 ↑     ↑ ↑ ↑
               tap7  tap5,4,3

Paso 1:
  Nuevo bit = bit[7] ⊕ bit[5] ⊕ bit[4] ⊕ bit[3]
            = 1 ⊕ 1 ⊕ 0 ⊕ 0 = 0
  
  Desplazar derecha, insertar nuevo bit a la izquierda:
  [0,1,0,1,1,0,0,1]
```

### 4.3 Uso para Cifrado de Flujo

```
Texto plano:    01001000 01101111 01101100 01100001  ("Hola")
Keystream:      10101100 11010010 01110011 10100101  (generado por LFSR)
                ─────────────────────────────────────
Texto cifrado:  11100100 10111101 00011111 11000100  (XOR)
```

### Captura: Interfaz LFSR

![Captura de la interfaz LFSR - Cifrado de flujo](screenshots/lfsr_interface.png)

*Figura 10: Interfaz del cifrado LFSR mostrando el mensaje, la semilla (seed) y el resultado cifrado en hexadecimal.*

---

### Captura: Visualización LFSR

![Captura de visualización LFSR - Estados del registro paso a paso](screenshots/lfsr_visualize.png)

*Figura 11: Visualización del proceso LFSR mostrando los estados del registro, el keystream generado y la operación XOR.*

---

### 4.4 Debilidades

| Vulnerabilidad | Descripción |
|----------------|-------------|
| **Linealidad** | Si se conoce suficiente keystream, se puede recuperar el estado |
| **Conocido-Plaintext** | Con texto plano conocido, se deduce el keystream |
| **Berlekamp-Massey** | Algoritmo que rompe LFSR con 2n bits de salida |

---

## 5. Algoritmo César

### 5.1 Historia y Concepto

El cifrado César es uno de los más antiguos, usado por Julio César para comunicarse con sus generales.

### 5.2 Funcionamiento Técnico

```
Alfabeto:  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
Posición:  0 1 2 3 4 5 6 7 8 9 ...

Cifrado:   C = (P + K) mod 26
Descifrado: P = (C - K) mod 26

Ejemplo con K=3:
  'H' (pos 7) → (7 + 3) mod 26 = 10 → 'K'
  'O' (pos 14) → (14 + 3) mod 26 = 17 → 'R'
  'L' (pos 11) → (11 + 3) mod 26 = 14 → 'O'
  'A' (pos 0) → (0 + 3) mod 26 = 3 → 'D'
  
  "HOLA" → "KROD"
```

### Captura: Interfaz César

![Captura de la interfaz César - Cifrado y descifrado](screenshots/caesar_interface.png)

*Figura 12: Interfaz del cifrado César mostrando el mensaje original, el desplazamiento y el texto cifrado resultante.*

---

### Captura: Demo Rápida César (Dashboard)

![Captura de Demo Rápida César en el Dashboard](screenshots/caesar_demo.png)

*Figura 13: Demo rápida de cifrado César en el dashboard principal, permitiendo probar el cifrado de forma inmediata.*

---

### 5.3 Por Qué es Inseguro

1. **Espacio de claves diminuto:** Solo 26 posibilidades
2. **Vulnerable a fuerza bruta:** Se prueba todo en milisegundos
3. **Análisis de frecuencia:** Las letras mantienen su frecuencia relativa

---

## 6. Otros Algoritmos en el Mercado

### 6.1 Tabla Comparativa

| Algoritmo | Tipo | Clave | Seguridad | Velocidad | Estado |
|-----------|------|-------|-----------|-----------|--------|
| **DES** | Bloque | 56 bits | ❌ Roto | Rápido | Obsoleto |
| **3DES** | Bloque | 168 bits | ⚠️ Débil | Lento | Legado |
| **AES** | Bloque | 128-256 | ✅ Seguro | Muy rápido | Estándar |
| **ChaCha20** | Flujo | 256 bits | ✅ Seguro | Muy rápido | Moderno |
| **Blowfish** | Bloque | 32-448 | ✅ Seguro | Rápido | Legado |
| **Twofish** | Bloque | 128-256 | ✅ Seguro | Rápido | Alternativa |
| **RSA** | Asimétrico | 2048+ | ✅ Seguro | Lento | Estándar |
| **ECC** | Asimétrico | 256+ | ✅ Muy seguro | Rápido | Moderno |

### 6.2 Análisis Detallado

#### DES (Data Encryption Standard)
**Ventajas:**
- Bien estudiado y documentado
- Simple de implementar

**Desventajas:**
- ❌ Clave de 56 bits es muy corta (roto en 1999)
- ❌ Bloque de 64 bits propenso a ataques
- ❌ Obsoleto, no debe usarse

#### AES (Advanced Encryption Standard)
**Ventajas:**
- ✅ Estándar mundial, extremadamente auditado
- ✅ Aceleración en hardware (instrucciones AES-NI)
- ✅ Flexible: 128/192/256 bits
- ✅ Sin ataques prácticos conocidos

**Desventajas:**
- ⚠️ Vulnerable a ataques de canal lateral si mal implementado

#### RSA
**Ventajas:**
- ✅ Bien entendido matemáticamente
- ✅ Proporciona no repudio
- ✅ Estándar para intercambio de claves

**Desventajas:**
- ❌ Claves muy grandes (2048-4096 bits)
- ❌ Operaciones lentas
- ❌ Vulnerable a computación cuántica (Shor)

### Captura: Tabla Comparativa en el Sistema

![Captura de tabla comparativa de algoritmos](screenshots/tabla_comparativa.png)

*Figura 14: Tabla comparativa de algoritmos en la interfaz del sistema, mostrando tipo, seguridad, velocidad y uso recomendado.*

---

## 7. Ataques más Comunes

### 7.1 Ataque de Fuerza Bruta

#### ¿Cómo funciona?

Probar **exhaustivamente todas las combinaciones posibles** de claves hasta encontrar la correcta.

#### Estimación de Tiempo

| Longitud | Charset | Combinaciones | Tiempo (1M/s) |
|----------|---------|---------------|---------------|
| 4 | a-z (26) | 456,976 | < 1 seg |
| 6 | a-z (26) | 308 millones | 5 min |
| 8 | a-zA-Z0-9 (62) | 218 billones | 7 años |
| 12 | Todo ASCII (95) | 5.4 × 10^23 | Trillones de años |

### Captura: Ataque Fuerza Bruta César

![Captura de ataque fuerza bruta a César](screenshots/bruteforce_caesar.png)

*Figura 15: Resultado del ataque de fuerza bruta al cifrado César, mostrando todos los candidatos ordenados por puntuación de frecuencia.*

---

### Captura: Estimador de Tiempo de Ataque

![Captura del estimador de tiempo de fuerza bruta](screenshots/bruteforce_estimator.png)

*Figura 16: Estimador de tiempo mostrando cuánto tomaría un ataque de fuerza bruta según la longitud y conjunto de caracteres.*

---

### 7.2 Ataque Man-in-the-Middle (MITM)

#### ¿Cómo funciona?

El atacante se posiciona entre dos partes comunicándose:

```
    Sin MITM:
    Alice ◄──────────────────► Bob
    
    Con MITM:
    Alice ◄───► Eve ◄───► Bob
                 ↑
            Atacante
```

#### Escenarios Simulados

1. **Sin cifrado** - Eve lee y modifica todo
2. **DH sin autenticación** - Eve intercambia claves con ambas partes
3. **Con firma digital** - Eve detectada al no poder falsificar firmas

### Captura: Simulación MITM Sin Cifrado

![Captura de simulación MITM sin cifrado](screenshots/mitm_unencrypted.png)

*Figura 17: Simulación de ataque MITM en comunicación sin cifrar, mostrando cómo Eve intercepta y modifica el mensaje.*

---

### Captura: Simulación MITM Diffie-Hellman

![Captura de simulación MITM en Diffie-Hellman](screenshots/mitm_diffie_hellman.png)

*Figura 18: Simulación de ataque MITM en intercambio Diffie-Hellman sin autenticación, mostrando cómo Eve establece secretos separados.*

---

### Captura: MITM Protegido con Firma Digital

![Captura de MITM protegido con firma digital](screenshots/mitm_protected.png)

*Figura 19: Demostración de cómo la firma digital previene el ataque MITM al detectar la falsificación.*

---

### 7.3 Herramientas de Kali Linux

#### Cracking de Contraseñas

```bash
# Hashcat - Cracking con GPU
hashcat -m 0 -a 0 hashes.txt rockyou.txt

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Hydra - Ataques en línea
hydra -l admin -P passwords.txt ssh://192.168.1.100
```

#### Ataques MITM

```bash
# ARP Spoofing
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1

# Ettercap
ettercap -T -M arp:remote /192.168.1.100// /192.168.1.1//

# Bettercap
bettercap -iface eth0
> net.probe on
> arp.spoof on
```

### Captura: Información de Herramientas Kali

![Captura de sección de herramientas Kali Linux](screenshots/kali_tools.png)

*Figura 20: Sección de herramientas de Kali Linux en el sistema, mostrando Hashcat, John, Hydra, Wireshark, Ettercap y Bettercap.*

---

### 7.4 Cómo Descifrar Algo

#### Metodología de Análisis

```
┌─────────────────────────────────────────────────────────┐
│  1. IDENTIFICAR EL TIPO DE CIFRADO                      │
├─────────────────────────────────────────────────────────┤
│  • ¿Es Base64? (caracteres A-Za-z0-9+/=)               │
│  • ¿Es Hexadecimal? (0-9A-Fa-f)                        │
│  • ¿Es ROT13/César? (solo letras)                      │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│  2. ANÁLISIS DE FRECUENCIA                              │
├─────────────────────────────────────────────────────────┤
│  • Contar frecuencia de caracteres                      │
│  • Comparar con frecuencias del idioma esperado         │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│  3. PROBAR ATAQUES CONOCIDOS                            │
├─────────────────────────────────────────────────────────┤
│  • César: Probar 26 desplazamientos                     │
│  • XOR: Probar claves cortas comunes                    │
└─────────────────────────────────────────────────────────┘
```

### Captura: Análisis de Frecuencia

![Captura del análisis de frecuencia](screenshots/frequency_analysis.png)

*Figura 21: Herramienta de análisis de frecuencia mostrando la distribución de caracteres en un texto cifrado.*

---

### Captura: Sección de Defensas

![Captura de tabla de defensas y contramedidas](screenshots/defensas.png)

*Figura 22: Tabla de defensas y contramedidas para cada tipo de ataque, incluyendo implementaciones recomendadas.*

---

## Conclusiones

1. **La autenticación de mensajes es fundamental** - HMAC para velocidad, firmas digitales para no repudio
2. **AES es el estándar actual** - Usar AES-256-GCM para cifrado autenticado
3. **Los algoritmos propios son solo educativos** - Nunca usar en producción
4. **Los ataques evolucionan constantemente** - Mantener sistemas actualizados
5. **La seguridad es multicapa** - Combinar cifrado, autenticación, y buenas prácticas

---

## Referencias

- NIST FIPS 197 - Advanced Encryption Standard (AES)
- RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
- RFC 8017 - PKCS #1: RSA Cryptography Specifications
- Applied Cryptography - Bruce Schneier
- Kali Linux Documentation - https://www.kali.org/docs/

---

## Anexo: Instrucciones para Capturas

Para agregar las capturas de pantalla:

1. Crear directorio: `docs/screenshots/`
2. Acceder a http://127.0.0.1:8000
3. Tomar capturas de cada funcionalidad
4. Guardar con los nombres indicados en cada figura
5. Las imágenes se mostrarán automáticamente en el documento
