"""
AES - Advanced Encryption Standard
===================================
AES es el estándar de cifrado simétrico más utilizado actualmente.
Fue adoptado por NIST en 2001 para reemplazar a DES.

Características técnicas:
- Cifrado de bloque de 128 bits
- Claves de 128, 192 o 256 bits
- Estructura de red de sustitución-permutación (SPN)

Pasos del algoritmo (para cada ronda):
1. SubBytes: Sustitución no lineal usando S-Box
2. ShiftRows: Permutación de filas de la matriz de estado
3. MixColumns: Mezcla de columnas mediante multiplicación en GF(2^8)
4. AddRoundKey: XOR con la subclave de la ronda

Este módulo proporciona una interfaz educativa para entender AES,
utilizando la librería pycryptodome para la implementación real.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64


class AESDemo:
    """
    Demostración educativa de AES con diferentes modos de operación.
    """
    
    # S-Box de AES (tabla de sustitución)
    S_BOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    
    def __init__(self, key: bytes = None, mode: str = 'CBC'):
        """
        Inicializa el cifrador AES.
        
        Args:
            key: Clave de 16, 24 o 32 bytes (128, 192 o 256 bits)
            mode: Modo de operación ('ECB', 'CBC', 'CTR')
        """
        if key is None:
            key = get_random_bytes(16)  # AES-128 por defecto
        
        if len(key) not in [16, 24, 32]:
            raise ValueError("La clave debe ser de 16, 24 o 32 bytes")
        
        self.key = key
        self.mode = mode
        self.block_size = 16  # AES siempre usa bloques de 128 bits
    
    def encrypt(self, plaintext: str) -> dict:
        """
        Cifra un mensaje usando AES.
        
        Args:
            plaintext: Texto plano a cifrar
            
        Returns:
            Diccionario con ciphertext, IV (si aplica), y metadatos
        """
        plaintext_bytes = plaintext.encode('utf-8')
        
        if self.mode == 'ECB':
            cipher = AES.new(self.key, AES.MODE_ECB)
            padded = pad(plaintext_bytes, self.block_size)
            ciphertext = cipher.encrypt(padded)
            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'ciphertext_hex': ciphertext.hex(),
                'mode': 'ECB',
                'key_size': len(self.key) * 8,
                'warning': 'ECB no es seguro para datos con patrones repetitivos'
            }
        
        elif self.mode == 'CBC':
            iv = get_random_bytes(16)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            padded = pad(plaintext_bytes, self.block_size)
            ciphertext = cipher.encrypt(padded)
            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'ciphertext_hex': ciphertext.hex(),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'iv_hex': iv.hex(),
                'mode': 'CBC',
                'key_size': len(self.key) * 8
            }
        
        elif self.mode == 'CTR':
            cipher = AES.new(self.key, AES.MODE_CTR)
            ciphertext = cipher.encrypt(plaintext_bytes)
            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'ciphertext_hex': ciphertext.hex(),
                'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
                'mode': 'CTR',
                'key_size': len(self.key) * 8
            }
    
    def decrypt(self, ciphertext_b64: str, iv_b64: str = None, nonce_b64: str = None) -> str:
        """
        Descifra un mensaje cifrado con AES.
        
        Args:
            ciphertext_b64: Texto cifrado en base64
            iv_b64: IV en base64 (para CBC)
            nonce_b64: Nonce en base64 (para CTR)
            
        Returns:
            Texto plano original
        """
        ciphertext = base64.b64decode(ciphertext_b64)
        
        if self.mode == 'ECB':
            cipher = AES.new(self.key, AES.MODE_ECB)
            padded = cipher.decrypt(ciphertext)
            plaintext = unpad(padded, self.block_size)
        
        elif self.mode == 'CBC':
            iv = base64.b64decode(iv_b64)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            padded = cipher.decrypt(ciphertext)
            plaintext = unpad(padded, self.block_size)
        
        elif self.mode == 'CTR':
            nonce = base64.b64decode(nonce_b64)
            cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
        
        return plaintext.decode('utf-8')
    
    def explain_subbytes(self, byte_value: int) -> dict:
        """
        Explica la operación SubBytes para un byte específico.
        
        Args:
            byte_value: Valor del byte (0-255)
            
        Returns:
            Diccionario con la explicación del proceso
        """
        row = (byte_value >> 4) & 0x0F
        col = byte_value & 0x0F
        result = self.S_BOX[byte_value]
        
        return {
            'input': f'0x{byte_value:02x}',
            'input_binary': format(byte_value, '08b'),
            'row': row,
            'col': col,
            'output': f'0x{result:02x}',
            'output_binary': format(result, '08b'),
            'explanation': f'S-Box[{row}][{col}] = 0x{result:02x}'
        }
    
    def explain_shiftrows(self, state: list) -> dict:
        """
        Explica la operación ShiftRows.
        
        Args:
            state: Matriz de estado 4x4 (lista de 16 bytes)
            
        Returns:
            Diccionario con el estado antes y después
        """
        # Convertir a matriz 4x4
        matrix = [state[i:i+4] for i in range(0, 16, 4)]
        
        # Aplicar ShiftRows
        shifted = [
            matrix[0],  # Fila 0: sin cambios
            matrix[1][1:] + matrix[1][:1],  # Fila 1: rotar 1 izquierda
            matrix[2][2:] + matrix[2][:2],  # Fila 2: rotar 2 izquierda
            matrix[3][3:] + matrix[3][:3],  # Fila 3: rotar 3 izquierda
        ]
        
        return {
            'before': matrix,
            'after': shifted,
            'explanation': [
                'Fila 0: Sin cambios',
                'Fila 1: Rotar 1 posición a la izquierda',
                'Fila 2: Rotar 2 posiciones a la izquierda',
                'Fila 3: Rotar 3 posiciones a la izquierda'
            ]
        }
    
    @staticmethod
    def get_algorithm_info() -> dict:
        """Retorna información técnica sobre AES."""
        return {
            'name': 'AES - Advanced Encryption Standard',
            'type': 'Cifrado de bloque simétrico',
            'block_size': '128 bits',
            'key_sizes': ['128 bits (10 rondas)', '192 bits (12 rondas)', '256 bits (14 rondas)'],
            'structure': 'Red de Sustitución-Permutación (SPN)',
            'operations': {
                'SubBytes': 'Sustitución no lineal usando S-Box de 256 bytes',
                'ShiftRows': 'Permutación cíclica de las filas del estado',
                'MixColumns': 'Mezcla de columnas en el campo GF(2^8)',
                'AddRoundKey': 'XOR del estado con la subclave de la ronda'
            },
            'security': {
                'best_attack': 'Ataque biclique (2^126.1 para AES-128)',
                'practical_security': 'Sin ataques prácticos conocidos',
                'quantum_resistance': 'AES-256 resistente a Grover (efectivamente 128 bits)'
            },
            'usage': ['TLS/SSL', 'VPNs', 'Cifrado de disco', 'WiFi (WPA2/WPA3)']
        }


def demo():
    """Demostración de AES."""
    print("=== Demostración AES ===\n")
    
    # Crear clave de ejemplo
    key = b'MiClaveSecreta16'  # 16 bytes = 128 bits
    
    # Modo CBC
    aes_cbc = AESDemo(key=key, mode='CBC')
    mensaje = "Este es un mensaje secreto para demostrar AES!"
    
    print(f"Mensaje original: {mensaje}")
    print(f"Longitud: {len(mensaje)} caracteres\n")
    
    # Cifrar
    resultado = aes_cbc.encrypt(mensaje)
    print("Resultado del cifrado (CBC):")
    for k, v in resultado.items():
        print(f"  {k}: {v}")
    
    # Descifrar
    descifrado = aes_cbc.decrypt(resultado['ciphertext'], resultado['iv'])
    print(f"\nMensaje descifrado: {descifrado}")
    
    # Mostrar SubBytes
    print("\n--- Ejemplo SubBytes ---")
    subbytes = aes_cbc.explain_subbytes(0x53)
    for k, v in subbytes.items():
        print(f"  {k}: {v}")
    
    # Info del algoritmo
    print("\n--- Información técnica ---")
    info = AESDemo.get_algorithm_info()
    print(f"Nombre: {info['name']}")
    print(f"Tipo: {info['type']}")
    print(f"Tamaños de clave: {', '.join(info['key_sizes'])}")


if __name__ == "__main__":
    demo()
