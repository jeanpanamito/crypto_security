"""
Algoritmo Asimétrico Propio - SimpleRSA
========================================
Implementación simplificada de criptografía asimétrica basada en RSA.
Diseñado con fines educativos para demostrar los principios de:

1. Generación de par de claves (pública/privada)
2. Cifrado con clave pública
3. Descifrado con clave privada
4. Firma digital

Fundamentos matemáticos:
- Basado en la dificultad de factorizar números grandes
- n = p * q (producto de dos primos)
- φ(n) = (p-1)(q-1) (función de Euler)
- e * d ≡ 1 (mod φ(n)) (inverso modular)
- Cifrado: c = m^e mod n
- Descifrado: m = c^d mod n

ADVERTENCIA: Usa números primos pequeños para demostración.
NO usar en producción.
"""

import random
import math


class SimpleRSA:
    """
    Implementación educativa de RSA con números pequeños.
    Demuestra los conceptos fundamentales de criptografía asimétrica.
    """
    
    # Primos pequeños para demostración
    SMALL_PRIMES = [
        101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
        151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
        199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
        263, 269, 271, 277, 281, 283, 293, 307, 311, 313
    ]
    
    def __init__(self, key_size: str = 'small'):
        """
        Inicializa el sistema RSA generando un par de claves.
        
        Args:
            key_size: 'small' para demo, 'medium' para valores más grandes
        """
        self.p = None
        self.q = None
        self.n = None
        self.phi_n = None
        self.e = None
        self.d = None
        
        self.generate_keys(key_size)
    
    def _is_prime(self, n: int) -> bool:
        """Verifica si un número es primo usando prueba simple."""
        if n < 2:
            return False
        if n == 2:
            return True
        if n % 2 == 0:
            return False
        for i in range(3, int(math.sqrt(n)) + 1, 2):
            if n % i == 0:
                return False
        return True
    
    def _gcd(self, a: int, b: int) -> int:
        """Calcula el máximo común divisor."""
        while b:
            a, b = b, a % b
        return a
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """
        Calcula el inverso modular de a mod m usando el algoritmo extendido de Euclides.
        """
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        _, x, _ = extended_gcd(a % m, m)
        return (x % m + m) % m
    
    def generate_keys(self, key_size: str = 'small'):
        """
        Genera un par de claves RSA.
        
        Args:
            key_size: Tamaño de clave ('small' o 'medium')
        """
        if key_size == 'small':
            primes = self.SMALL_PRIMES[:20]
        else:
            primes = self.SMALL_PRIMES
        
        # Seleccionar dos primos diferentes
        self.p = random.choice(primes)
        self.q = random.choice([x for x in primes if x != self.p])
        
        # Calcular n = p * q
        self.n = self.p * self.q
        
        # Calcular φ(n) = (p-1)(q-1)
        self.phi_n = (self.p - 1) * (self.q - 1)
        
        # Elegir e: 1 < e < φ(n), coprimo con φ(n)
        # Usualmente se usa 65537, pero para demo usamos valores pequeños
        for e in [65537, 17, 5, 3]:
            if e < self.phi_n and self._gcd(e, self.phi_n) == 1:
                self.e = e
                break
        
        # Calcular d: inverso modular de e mod φ(n)
        self.d = self._mod_inverse(self.e, self.phi_n)
    
    def get_public_key(self) -> tuple:
        """Retorna la clave pública (e, n)."""
        return (self.e, self.n)
    
    def get_private_key(self) -> tuple:
        """Retorna la clave privada (d, n)."""
        return (self.d, self.n)
    
    def encrypt_number(self, m: int) -> int:
        """
        Cifra un número usando la clave pública.
        
        Args:
            m: Número a cifrar (debe ser menor que n)
            
        Returns:
            Número cifrado
        """
        if m >= self.n:
            raise ValueError(f"El mensaje debe ser menor que n={self.n}")
        return pow(m, self.e, self.n)
    
    def decrypt_number(self, c: int) -> int:
        """
        Descifra un número usando la clave privada.
        
        Args:
            c: Número cifrado
            
        Returns:
            Número original
        """
        return pow(c, self.d, self.n)
    
    def encrypt(self, plaintext: str) -> list:
        """
        Cifra un mensaje de texto.
        
        Args:
            plaintext: Texto a cifrar
            
        Returns:
            Lista de números cifrados (uno por carácter)
        """
        return [self.encrypt_number(ord(char)) for char in plaintext]
    
    def decrypt(self, ciphertext: list) -> str:
        """
        Descifra un mensaje.
        
        Args:
            ciphertext: Lista de números cifrados
            
        Returns:
            Texto plano original
        """
        return ''.join([chr(self.decrypt_number(c)) for c in ciphertext])
    
    def sign(self, message: str) -> list:
        """
        Firma un mensaje (usa clave privada para "cifrar" el hash).
        
        Args:
            message: Mensaje a firmar
            
        Returns:
            Firma (lista de números)
        """
        # Usamos un hash simple para demostración
        hash_value = sum(ord(c) for c in message) % self.n
        signature = pow(hash_value, self.d, self.n)
        return signature, hash_value
    
    def verify(self, message: str, signature: int) -> bool:
        """
        Verifica una firma digital.
        
        Args:
            message: Mensaje original
            signature: Firma a verificar
            
        Returns:
            True si la firma es válida
        """
        # Recalcular hash del mensaje
        hash_value = sum(ord(c) for c in message) % self.n
        # "Descifrar" la firma con clave pública
        recovered_hash = pow(signature, self.e, self.n)
        return hash_value == recovered_hash
    
    def get_key_info(self) -> dict:
        """Retorna información detallada de las claves."""
        return {
            'p': self.p,
            'q': self.q,
            'n': self.n,
            'phi_n': self.phi_n,
            'e': self.e,
            'd': self.d,
            'public_key': f'({self.e}, {self.n})',
            'private_key': f'({self.d}, {self.n})',
            'bit_length': self.n.bit_length()
        }
    
    def visualize_encryption(self, char: str) -> dict:
        """
        Visualiza el proceso de cifrado de un carácter.
        
        Args:
            char: Carácter a cifrar
            
        Returns:
            Diccionario con los pasos del proceso
        """
        m = ord(char)
        c = self.encrypt_number(m)
        d_check = self.decrypt_number(c)
        
        return {
            'character': char,
            'ascii_value': m,
            'public_key': f'(e={self.e}, n={self.n})',
            'formula': f'c = m^e mod n = {m}^{self.e} mod {self.n}',
            'ciphertext': c,
            'decryption_formula': f'm = c^d mod n = {c}^{self.d} mod {self.n}',
            'decrypted_value': d_check,
            'recovered_char': chr(d_check)
        }
    
    @staticmethod
    def get_algorithm_info() -> dict:
        """Retorna información técnica del algoritmo."""
        return {
            'name': 'SimpleRSA (RSA Educativo)',
            'type': 'Cifrado asimétrico',
            'basis': 'Dificultad de factorización de números grandes',
            'key_components': {
                'p, q': 'Números primos secretos',
                'n': 'Módulo público (p × q)',
                'e': 'Exponente público',
                'd': 'Exponente privado (inverso de e mod φ(n))'
            },
            'operations': {
                'cifrado': 'c = m^e mod n',
                'descifrado': 'm = c^d mod n',
                'firma': 's = hash(m)^d mod n',
                'verificación': 'hash(m) == s^e mod n'
            },
            'security_note': 'DEMO EDUCATIVA - Los primos reales deben tener 2048+ bits'
        }


def demo():
    """Demostración del algoritmo SimpleRSA."""
    print("=== Demostración SimpleRSA (Algoritmo Asimétrico Propio) ===\n")
    
    rsa = SimpleRSA(key_size='small')
    
    # Mostrar información de claves
    print("--- Generación de Claves ---")
    info = rsa.get_key_info()
    print(f"  p (primo 1): {info['p']}")
    print(f"  q (primo 2): {info['q']}")
    print(f"  n = p × q: {info['n']}")
    print(f"  φ(n) = (p-1)(q-1): {info['phi_n']}")
    print(f"  e (exponente público): {info['e']}")
    print(f"  d (exponente privado): {info['d']}")
    print(f"  Clave pública: {info['public_key']}")
    print(f"  Clave privada: {info['private_key']}")
    
    # Cifrar mensaje
    mensaje = "Hola"
    print(f"\n--- Cifrado de Mensaje: '{mensaje}' ---")
    
    ciphertext = rsa.encrypt(mensaje)
    print(f"Texto cifrado (números): {ciphertext}")
    
    decrypted = rsa.decrypt(ciphertext)
    print(f"Texto descifrado: {decrypted}")
    
    # Visualizar proceso
    print("\n--- Proceso Detallado para 'H' ---")
    vis = rsa.visualize_encryption('H')
    for k, v in vis.items():
        print(f"  {k}: {v}")
    
    # Firma digital
    print("\n--- Firma Digital ---")
    signature, hash_val = rsa.sign(mensaje)
    print(f"Hash del mensaje: {hash_val}")
    print(f"Firma: {signature}")
    
    is_valid = rsa.verify(mensaje, signature)
    print(f"¿Firma válida?: {is_valid}")
    
    # Verificar con mensaje alterado
    is_valid_fake = rsa.verify(mensaje + "!", signature)
    print(f"¿Firma válida con mensaje alterado?: {is_valid_fake}")


if __name__ == "__main__":
    demo()
