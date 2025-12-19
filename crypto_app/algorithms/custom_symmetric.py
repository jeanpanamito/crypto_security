"""
Algoritmo Simétrico Propio - CipherX
=====================================
Algoritmo de cifrado de bloque diseñado con fines educativos.
Combina técnicas clásicas de criptografía:

1. Sustitución (S-Box personalizada)
2. Permutación de bits
3. Mezcla con XOR de subclave
4. Múltiples rondas

ADVERTENCIA: Este algoritmo es solo educativo y NO debe usarse
para proteger información sensible en producción.

Especificaciones:
- Tamaño de bloque: 64 bits (8 bytes)
- Tamaño de clave: 64 bits (8 bytes)
- Número de rondas: 4
"""

import struct


class CipherX:
    """
    Algoritmo de cifrado simétrico propio con fines educativos.
    Implementa una estructura de Red de Sustitución-Permutación (SPN).
    """
    
    # S-Box personalizada (4 bits -> 4 bits)
    # Diseñada para maximizar la no-linealidad
    S_BOX = [
        0x6, 0x4, 0xC, 0x5, 0x0, 0x7, 0x2, 0xE,
        0x1, 0xF, 0x3, 0xD, 0x8, 0xA, 0x9, 0xB
    ]
    
    # S-Box inversa para descifrado
    S_BOX_INV = [
        0x4, 0x8, 0x6, 0xA, 0x1, 0x3, 0x0, 0x5,
        0xC, 0xE, 0xD, 0xF, 0x2, 0xB, 0x7, 0x9
    ]
    
    # Tabla de permutación de bits (64 bits)
    P_BOX = [
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8, 0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6
    ]
    
    # Permutación inversa
    P_BOX_INV = [0] * 64
    for i, p in enumerate(P_BOX):
        P_BOX_INV[p] = i
    
    def __init__(self, key: bytes, rounds: int = 4):
        """
        Inicializa el cifrador.
        
        Args:
            key: Clave de 8 bytes (64 bits)
            rounds: Número de rondas (default: 4)
        """
        if len(key) != 8:
            raise ValueError("La clave debe ser de 8 bytes")
        
        self.key = key
        self.rounds = rounds
        self.subkeys = self._generate_subkeys()
    
    def _generate_subkeys(self) -> list:
        """
        Genera las subclaves para cada ronda mediante rotación.
        
        Returns:
            Lista de subclaves (una por ronda + 1 para whitening final)
        """
        key_int = struct.unpack('>Q', self.key)[0]
        subkeys = []
        
        for i in range(self.rounds + 1):
            # Rotar la clave y mezclar con constante de ronda
            rotated = ((key_int << (i * 3)) | (key_int >> (64 - i * 3))) & 0xFFFFFFFFFFFFFFFF
            round_constant = 0x9E3779B97F4A7C15 * (i + 1)  # Constante derivada del número áureo
            subkey = rotated ^ round_constant
            subkeys.append(subkey & 0xFFFFFFFFFFFFFFFF)
        
        return subkeys
    
    def _apply_sbox(self, value: int, inverse: bool = False) -> int:
        """
        Aplica la S-Box a un valor de 64 bits (16 nibbles).
        
        Args:
            value: Valor de 64 bits
            inverse: Si True, usa la S-Box inversa
            
        Returns:
            Valor sustituido
        """
        sbox = self.S_BOX_INV if inverse else self.S_BOX
        result = 0
        
        for i in range(16):  # 16 nibbles de 4 bits
            nibble = (value >> (i * 4)) & 0xF
            substituted = sbox[nibble]
            result |= substituted << (i * 4)
        
        return result
    
    def _apply_pbox(self, value: int, inverse: bool = False) -> int:
        """
        Aplica la permutación de bits.
        
        Args:
            value: Valor de 64 bits
            inverse: Si True, usa la permutación inversa
            
        Returns:
            Valor permutado
        """
        pbox = self.P_BOX_INV if inverse else self.P_BOX
        result = 0
        
        for i in range(64):
            if value & (1 << i):
                result |= 1 << pbox[i]
        
        return result
    
    def _encrypt_block(self, block: int) -> int:
        """
        Cifra un bloque de 64 bits.
        
        Args:
            block: Bloque de 64 bits
            
        Returns:
            Bloque cifrado
        """
        state = block
        
        # Rondas de cifrado
        for i in range(self.rounds):
            # 1. XOR con subclave
            state ^= self.subkeys[i]
            # 2. Sustitución (S-Box)
            state = self._apply_sbox(state)
            # 3. Permutación (P-Box)
            state = self._apply_pbox(state)
        
        # Whitening final
        state ^= self.subkeys[self.rounds]
        
        return state
    
    def _decrypt_block(self, block: int) -> int:
        """
        Descifra un bloque de 64 bits.
        
        Args:
            block: Bloque cifrado
            
        Returns:
            Bloque descifrado
        """
        state = block
        
        # Quitar whitening final
        state ^= self.subkeys[self.rounds]
        
        # Rondas inversas
        for i in range(self.rounds - 1, -1, -1):
            # 1. Permutación inversa
            state = self._apply_pbox(state, inverse=True)
            # 2. S-Box inversa
            state = self._apply_sbox(state, inverse=True)
            # 3. XOR con subclave
            state ^= self.subkeys[i]
        
        return state
    
    def encrypt(self, plaintext: str) -> str:
        """
        Cifra un mensaje completo.
        
        Args:
            plaintext: Texto plano
            
        Returns:
            Texto cifrado en hexadecimal
        """
        # Convertir a bytes y aplicar padding
        data = plaintext.encode('utf-8')
        padding_len = (8 - len(data) % 8) % 8
        if padding_len == 0:
            padding_len = 8
        data += bytes([padding_len] * padding_len)
        
        # Cifrar bloque por bloque
        ciphertext = b''
        for i in range(0, len(data), 8):
            block = struct.unpack('>Q', data[i:i+8])[0]
            encrypted_block = self._encrypt_block(block)
            ciphertext += struct.pack('>Q', encrypted_block)
        
        return ciphertext.hex()
    
    def decrypt(self, ciphertext_hex: str) -> str:
        """
        Descifra un mensaje.
        
        Args:
            ciphertext_hex: Texto cifrado en hexadecimal
            
        Returns:
            Texto plano original
        """
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        # Descifrar bloque por bloque
        plaintext = b''
        for i in range(0, len(ciphertext), 8):
            block = struct.unpack('>Q', ciphertext[i:i+8])[0]
            decrypted_block = self._decrypt_block(block)
            plaintext += struct.pack('>Q', decrypted_block)
        
        # Quitar padding
        padding_len = plaintext[-1]
        plaintext = plaintext[:-padding_len]
        
        return plaintext.decode('utf-8')
    
    def visualize_round(self, block: int, round_num: int) -> dict:
        """
        Visualiza una ronda de cifrado paso a paso.
        
        Args:
            block: Bloque inicial
            round_num: Número de ronda
            
        Returns:
            Diccionario con el estado en cada paso
        """
        state = block
        steps = {'input': format(state, '016x')}
        
        # XOR con subclave
        state ^= self.subkeys[round_num]
        steps['after_key_xor'] = format(state, '016x')
        
        # S-Box
        state = self._apply_sbox(state)
        steps['after_sbox'] = format(state, '016x')
        
        # P-Box
        state = self._apply_pbox(state)
        steps['after_pbox'] = format(state, '016x')
        
        return steps
    
    @staticmethod
    def get_algorithm_info() -> dict:
        """Retorna información técnica del algoritmo."""
        return {
            'name': 'CipherX (Algoritmo Educativo)',
            'type': 'Cifrado de bloque simétrico',
            'block_size': '64 bits',
            'key_size': '64 bits',
            'rounds': 4,
            'structure': 'Red de Sustitución-Permutación (SPN)',
            'components': {
                'S-Box': 'Tabla de sustitución 4x4 bits (16 entradas)',
                'P-Box': 'Permutación de 64 bits',
                'Key Schedule': 'Rotación + XOR con constante de ronda'
            },
            'security_note': 'SOLO PARA FINES EDUCATIVOS - No usar en producción'
        }


def demo():
    """Demostración del algoritmo CipherX."""
    print("=== Demostración CipherX (Algoritmo Simétrico Propio) ===\n")
    
    key = b'ClaveXYZ'  # 8 bytes
    cipher = CipherX(key)
    
    mensaje = "¡Hola Mundo!"
    print(f"Mensaje original: {mensaje}")
    print(f"Clave: {key.decode()}")
    
    # Cifrar
    ciphertext = cipher.encrypt(mensaje)
    print(f"Texto cifrado (hex): {ciphertext}")
    
    # Descifrar
    decrypted = cipher.decrypt(ciphertext)
    print(f"Texto descifrado: {decrypted}")
    
    # Visualizar ronda
    print("\n--- Visualización de Ronda 0 ---")
    block = struct.unpack('>Q', mensaje[:8].encode('utf-8').ljust(8, b'\x00'))[0]
    steps = cipher.visualize_round(block, 0)
    for step, value in steps.items():
        print(f"  {step}: 0x{value}")
    
    # Info
    print("\n--- Información del Algoritmo ---")
    info = cipher.get_algorithm_info()
    for k, v in info.items():
        if isinstance(v, dict):
            print(f"  {k}:")
            for k2, v2 in v.items():
                print(f"    - {k2}: {v2}")
        else:
            print(f"  {k}: {v}")


if __name__ == "__main__":
    demo()
