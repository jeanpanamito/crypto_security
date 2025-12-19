"""
Cifrado César - Algoritmo de sustitución monoalfabética
=========================================================
El cifrado César es uno de los cifrados más simples y conocidos.
Consiste en desplazar cada letra del alfabeto un número fijo de posiciones.

Técnicamente:
- Cifrado: C = (P + K) mod 26
- Descifrado: P = (C - K) mod 26
Donde P es el texto plano, C el texto cifrado, y K la clave (desplazamiento).
"""

import string


class CaesarCipher:
    """Implementación del cifrado César con soporte para mayúsculas, minúsculas y caracteres especiales."""
    
    def __init__(self, shift: int = 3):
        """
        Inicializa el cifrado César.
        
        Args:
            shift: Número de posiciones a desplazar (por defecto 3, el clásico de Julio César)
        """
        self.shift = shift % 26  # Normalizar el desplazamiento
        self.alphabet_lower = string.ascii_lowercase
        self.alphabet_upper = string.ascii_uppercase
    
    def encrypt(self, plaintext: str) -> str:
        """
        Cifra un mensaje usando el cifrado César.
        
        Args:
            plaintext: Texto plano a cifrar
            
        Returns:
            Texto cifrado
        """
        result = []
        
        for char in plaintext:
            if char in self.alphabet_lower:
                # Cifrar minúsculas
                idx = self.alphabet_lower.index(char)
                new_idx = (idx + self.shift) % 26
                result.append(self.alphabet_lower[new_idx])
            elif char in self.alphabet_upper:
                # Cifrar mayúsculas
                idx = self.alphabet_upper.index(char)
                new_idx = (idx + self.shift) % 26
                result.append(self.alphabet_upper[new_idx])
            else:
                # Mantener caracteres no alfabéticos
                result.append(char)
        
        return ''.join(result)
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Descifra un mensaje cifrado con César.
        
        Args:
            ciphertext: Texto cifrado
            
        Returns:
            Texto plano original
        """
        # Descifrar es cifrar con desplazamiento negativo
        original_shift = self.shift
        self.shift = -self.shift % 26
        result = self.encrypt(ciphertext)
        self.shift = original_shift
        return result
    
    def brute_force_decrypt(self, ciphertext: str) -> list:
        """
        Intenta descifrar probando todos los desplazamientos posibles (0-25).
        
        Args:
            ciphertext: Texto cifrado
            
        Returns:
            Lista de tuplas (desplazamiento, texto_descifrado)
        """
        results = []
        original_shift = self.shift
        
        for shift in range(26):
            self.shift = shift
            decrypted = self.decrypt(ciphertext)
            results.append((shift, decrypted))
        
        self.shift = original_shift
        return results
    
    @staticmethod
    def frequency_analysis(text: str) -> dict:
        """
        Realiza análisis de frecuencia de caracteres.
        
        Args:
            text: Texto a analizar
            
        Returns:
            Diccionario con frecuencias de cada letra
        """
        freq = {char: 0 for char in string.ascii_lowercase}
        total = 0
        
        for char in text.lower():
            if char in freq:
                freq[char] += 1
                total += 1
        
        # Convertir a porcentajes
        if total > 0:
            freq = {k: round(v / total * 100, 2) for k, v in freq.items()}
        
        return freq


def demo():
    """Demostración del cifrado César."""
    cipher = CaesarCipher(shift=3)
    
    mensaje = "Hola, este es un mensaje secreto!"
    print(f"Mensaje original: {mensaje}")
    
    cifrado = cipher.encrypt(mensaje)
    print(f"Mensaje cifrado: {cifrado}")
    
    descifrado = cipher.decrypt(cifrado)
    print(f"Mensaje descifrado: {descifrado}")
    
    print("\n--- Análisis de frecuencia ---")
    freq = cipher.frequency_analysis(mensaje)
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:5]
    print(f"Top 5 letras más frecuentes: {sorted_freq}")


if __name__ == "__main__":
    demo()
