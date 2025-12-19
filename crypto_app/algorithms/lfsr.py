"""
LFSR - Linear Feedback Shift Register (Algoritmo por Acarreo)
==============================================================
El LFSR es un registro de desplazamiento cuyo bit de entrada es una función
lineal de su estado anterior. Se usa para generar secuencias pseudoaleatorias
y como base para cifrados de flujo.

Funcionamiento técnico:
1. Se inicializa con una semilla (estado inicial)
2. En cada paso, se calcula un nuevo bit mediante XOR de bits seleccionados (taps)
3. El registro se desplaza y el nuevo bit entra por un extremo
4. El bit que sale se usa como salida del generador

Para cifrado:
- Se genera una secuencia de bits pseudoaleatorios (keystream)
- Se hace XOR con el texto plano bit a bit
"""


class LFSR:
    """
    Implementación de un Linear Feedback Shift Register.
    
    Ejemplo con registro de 8 bits y taps en posiciones 7, 5, 4, 3:
    x^8 + x^6 + x^5 + x^4 + 1 (polinomio primitivo)
    """
    
    def __init__(self, seed: int, taps: list, size: int = 8):
        """
        Inicializa el LFSR.
        
        Args:
            seed: Semilla inicial (debe ser != 0)
            taps: Lista de posiciones para el feedback (0-indexed desde la derecha)
            size: Tamaño del registro en bits
        """
        if seed == 0:
            raise ValueError("La semilla no puede ser 0")
        
        self.size = size
        self.taps = taps
        self.state = seed & ((1 << size) - 1)  # Máscara para limitar a 'size' bits
        self.initial_state = self.state
    
    def step(self) -> int:
        """
        Realiza un paso del LFSR.
        
        Returns:
            Bit de salida (el bit menos significativo antes del desplazamiento)
        """
        # Calcular bit de feedback mediante XOR de los taps
        feedback = 0
        for tap in self.taps:
            feedback ^= (self.state >> tap) & 1
        
        # Bit de salida
        output = self.state & 1
        
        # Desplazar y agregar bit de feedback
        self.state = (self.state >> 1) | (feedback << (self.size - 1))
        
        return output
    
    def generate_keystream(self, length: int) -> list:
        """
        Genera una secuencia de bits pseudoaleatorios.
        
        Args:
            length: Número de bits a generar
            
        Returns:
            Lista de bits (0s y 1s)
        """
        return [self.step() for _ in range(length)]
    
    def generate_bytes(self, num_bytes: int) -> bytes:
        """
        Genera bytes pseudoaleatorios.
        
        Args:
            num_bytes: Número de bytes a generar
            
        Returns:
            Bytes generados
        """
        result = []
        for _ in range(num_bytes):
            byte_val = 0
            for bit_pos in range(8):
                byte_val |= self.step() << bit_pos
            result.append(byte_val)
        return bytes(result)
    
    def reset(self):
        """Reinicia el LFSR a su estado inicial."""
        self.state = self.initial_state
    
    def get_state_binary(self) -> str:
        """Retorna el estado actual en formato binario."""
        return format(self.state, f'0{self.size}b')


class LFSRCipher:
    """
    Cifrado de flujo basado en LFSR.
    Usa XOR entre el keystream y el texto para cifrar/descifrar.
    """
    
    def __init__(self, seed: int, taps: list = None, size: int = 16):
        """
        Inicializa el cifrado LFSR.
        
        Args:
            seed: Semilla (clave) del cifrado
            taps: Posiciones de feedback (si None, usa un polinomio conocido)
            size: Tamaño del registro
        """
        # Polinomios primitivos comunes
        if taps is None:
            # x^16 + x^14 + x^13 + x^11 + 1
            taps = [15, 13, 12, 10]
        
        self.lfsr = LFSR(seed, taps, size)
        self.seed = seed
        self.taps = taps
        self.size = size
    
    def encrypt(self, plaintext: str) -> tuple:
        """
        Cifra un mensaje usando el cifrado de flujo LFSR.
        
        Args:
            plaintext: Texto plano a cifrar
            
        Returns:
            Tupla (texto_cifrado_hex, keystream_hex)
        """
        self.lfsr.reset()
        plaintext_bytes = plaintext.encode('utf-8')
        keystream = self.lfsr.generate_bytes(len(plaintext_bytes))
        
        # XOR byte a byte
        ciphertext = bytes([p ^ k for p, k in zip(plaintext_bytes, keystream)])
        
        return ciphertext.hex(), keystream.hex()
    
    def decrypt(self, ciphertext_hex: str) -> str:
        """
        Descifra un mensaje cifrado con LFSR.
        
        Args:
            ciphertext_hex: Texto cifrado en hexadecimal
            
        Returns:
            Texto plano original
        """
        self.lfsr.reset()
        ciphertext = bytes.fromhex(ciphertext_hex)
        keystream = self.lfsr.generate_bytes(len(ciphertext))
        
        # XOR byte a byte (mismo proceso que cifrado)
        plaintext_bytes = bytes([c ^ k for c, k in zip(ciphertext, keystream)])
        
        return plaintext_bytes.decode('utf-8')
    
    def visualize_process(self, text: str) -> dict:
        """
        Visualiza el proceso de cifrado paso a paso.
        
        Args:
            text: Texto a cifrar
            
        Returns:
            Diccionario con detalles del proceso
        """
        self.lfsr.reset()
        text_bytes = text.encode('utf-8')
        
        steps = []
        for i, byte in enumerate(text_bytes):
            initial_state = self.lfsr.get_state_binary()
            keystream_byte = 0
            
            for bit_pos in range(8):
                keystream_byte |= self.lfsr.step() << bit_pos
            
            cipher_byte = byte ^ keystream_byte
            
            steps.append({
                'position': i,
                'char': chr(byte) if 32 <= byte < 127 else f'\\x{byte:02x}',
                'plaintext_byte': format(byte, '08b'),
                'keystream_byte': format(keystream_byte, '08b'),
                'cipher_byte': format(cipher_byte, '08b'),
                'lfsr_state': initial_state
            })
        
        return {
            'seed': self.seed,
            'taps': self.taps,
            'register_size': self.size,
            'steps': steps
        }


def demo():
    """Demostración del cifrado LFSR."""
    print("=== Demostración LFSR ===\n")
    
    # Crear cifrador con semilla 0xACE1
    cipher = LFSRCipher(seed=0xACE1)
    
    mensaje = "Mensaje secreto!"
    print(f"Mensaje original: {mensaje}")
    
    ciphertext, keystream = cipher.encrypt(mensaje)
    print(f"Texto cifrado (hex): {ciphertext}")
    print(f"Keystream (hex): {keystream}")
    
    descifrado = cipher.decrypt(ciphertext)
    print(f"Mensaje descifrado: {descifrado}")
    
    print("\n--- Secuencia del LFSR (primeros 16 bits) ---")
    lfsr = LFSR(seed=0xACE1, taps=[15, 13, 12, 10], size=16)
    bits = lfsr.generate_keystream(16)
    print(f"Bits generados: {''.join(map(str, bits))}")


if __name__ == "__main__":
    demo()
