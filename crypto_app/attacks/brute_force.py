"""
Ataque de Fuerza Bruta
=======================
Demostración educativa de ataques de fuerza bruta contra cifrados débiles.

Tipos de ataques implementados:
1. Fuerza bruta exhaustiva (probar todas las claves)
2. Ataque de diccionario
3. Análisis de frecuencia

NOTA: Este módulo es SOLO EDUCATIVO para entender vulnerabilidades.
"""

import time
import string
from collections import Counter
from typing import Callable, Optional

# Frecuencias de letras en español
SPANISH_FREQUENCIES = {
    'e': 12.53, 'a': 11.72, 'o': 8.44, 's': 7.20, 'r': 6.87,
    'n': 6.71, 'i': 6.25, 'd': 5.86, 'l': 4.97, 'c': 4.68,
    't': 4.63, 'u': 3.93, 'm': 3.16, 'p': 2.51, 'b': 1.42,
    'g': 1.01, 'v': 1.00, 'y': 0.90, 'q': 0.88, 'h': 0.70,
    'f': 0.69, 'z': 0.52, 'j': 0.44, 'x': 0.22, 'w': 0.02,
    'k': 0.01
}

# Frecuencias de letras en inglés
ENGLISH_FREQUENCIES = {
    'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
    'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25,
    'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36,
    'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29,
    'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10,
    'z': 0.07
}


class BruteForceAttack:
    """
    Implementación de ataques de fuerza bruta contra diferentes cifrados.
    """
    
    def __init__(self):
        self.attempts = 0
        self.time_elapsed = 0
    
    def attack_caesar(self, ciphertext: str, known_word: str = None) -> dict:
        """
        Ataque de fuerza bruta contra cifrado César.
        Como el espacio de claves es solo 26, es trivial.
        
        Args:
            ciphertext: Texto cifrado
            known_word: Palabra conocida que debe aparecer en el texto
            
        Returns:
            Diccionario con resultados del ataque
        """
        start_time = time.time()
        results = []
        
        for shift in range(26):
            decrypted = self._caesar_decrypt(ciphertext, shift)
            
            # Calcular puntuación de frecuencia
            score = self._frequency_score(decrypted)
            
            result = {
                'shift': shift,
                'decrypted': decrypted,
                'frequency_score': round(score, 2)
            }
            
            # Si hay palabra conocida, verificar
            if known_word and known_word.lower() in decrypted.lower():
                result['contains_known_word'] = True
            
            results.append(result)
            self.attempts += 1
        
        self.time_elapsed = time.time() - start_time
        
        # Ordenar por puntuación de frecuencia
        results.sort(key=lambda x: x['frequency_score'], reverse=True)
        
        return {
            'attack_type': 'Fuerza Bruta - César',
            'ciphertext': ciphertext,
            'total_attempts': self.attempts,
            'time_seconds': round(self.time_elapsed, 6),
            'best_guess': results[0],
            'all_results': results,
            'key_space': 26,
            'complexity': 'O(26) - Trivial'
        }
    
    def _caesar_decrypt(self, text: str, shift: int) -> str:
        """Descifra texto con César dado un desplazamiento."""
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                decrypted = chr((ord(char) - base - shift) % 26 + base)
                result.append(decrypted)
            else:
                result.append(char)
        return ''.join(result)
    
    def _frequency_score(self, text: str, language: str = 'spanish') -> float:
        """
        Calcula qué tan similar es la frecuencia de letras al idioma esperado.
        Mayor puntuación = más probable que sea texto válido.
        """
        freqs = SPANISH_FREQUENCIES if language == 'spanish' else ENGLISH_FREQUENCIES
        
        # Contar letras
        letters = [c.lower() for c in text if c.isalpha()]
        if not letters:
            return 0
        
        counts = Counter(letters)
        total = len(letters)
        
        # Calcular correlación con frecuencias esperadas
        score = 0
        for letter, expected_freq in freqs.items():
            actual_freq = (counts.get(letter, 0) / total) * 100
            # Cuanto más cercana la frecuencia, mayor puntuación
            score += min(actual_freq, expected_freq)
        
        return score
    
    def dictionary_attack(self, ciphertext: str, decrypt_func: Callable, 
                         wordlist: list = None) -> dict:
        """
        Ataque de diccionario usando una lista de contraseñas comunes.
        
        Args:
            ciphertext: Texto cifrado
            decrypt_func: Función de descifrado que acepta (ciphertext, password)
            wordlist: Lista de contraseñas a probar
            
        Returns:
            Resultado del ataque
        """
        if wordlist is None:
            # Passwords más comunes
            wordlist = [
                "123456", "password", "12345678", "qwerty", "123456789",
                "12345", "1234", "111111", "1234567", "dragon",
                "123123", "baseball", "iloveyou", "trustno1", "sunshine",
                "master", "welcome", "shadow", "ashley", "football",
                "jesus", "michael", "ninja", "mustang", "password1",
                "clave", "admin", "root", "letmein", "monkey"
            ]
        
        start_time = time.time()
        self.attempts = 0
        
        for password in wordlist:
            self.attempts += 1
            try:
                decrypted = decrypt_func(ciphertext, password)
                if decrypted and self._looks_like_text(decrypted):
                    self.time_elapsed = time.time() - start_time
                    return {
                        'success': True,
                        'password_found': password,
                        'decrypted_text': decrypted,
                        'attempts': self.attempts,
                        'time_seconds': round(self.time_elapsed, 6)
                    }
            except:
                continue
        
        self.time_elapsed = time.time() - start_time
        return {
            'success': False,
            'attempts': self.attempts,
            'time_seconds': round(self.time_elapsed, 6),
            'message': 'Contraseña no encontrada en el diccionario'
        }
    
    def _looks_like_text(self, text: str) -> bool:
        """Verifica si un texto parece ser legible."""
        if not text:
            return False
        
        # Contar caracteres imprimibles
        printable = sum(1 for c in text if c.isprintable())
        return printable / len(text) > 0.9
    
    def estimate_brute_force_time(self, key_length: int, charset_size: int,
                                  attempts_per_second: int = 1000000) -> dict:
        """
        Estima el tiempo necesario para un ataque de fuerza bruta.
        
        Args:
            key_length: Longitud de la clave
            charset_size: Tamaño del conjunto de caracteres
            attempts_per_second: Velocidad de ataque
            
        Returns:
            Estimación de tiempo
        """
        total_combinations = charset_size ** key_length
        seconds = total_combinations / attempts_per_second
        
        # Convertir a unidades legibles
        minutes = seconds / 60
        hours = minutes / 60
        days = hours / 24
        years = days / 365
        
        return {
            'key_length': key_length,
            'charset_size': charset_size,
            'total_combinations': f'{total_combinations:,}',
            'attempts_per_second': f'{attempts_per_second:,}',
            'time_estimate': {
                'seconds': round(seconds, 2) if seconds < 60 else 'N/A',
                'minutes': round(minutes, 2) if minutes < 60 else 'N/A',
                'hours': round(hours, 2) if hours < 24 else 'N/A',
                'days': round(days, 2) if days < 365 else 'N/A',
                'years': round(years, 2) if years >= 1 else 'N/A'
            },
            'conclusion': self._time_conclusion(years)
        }
    
    def _time_conclusion(self, years: float) -> str:
        """Genera una conclusión sobre la viabilidad del ataque."""
        if years < 0.001:
            return "⚠️ MUY VULNERABLE - Ataque factible en segundos"
        elif years < 1:
            return "⚠️ VULNERABLE - Ataque factible en meses"
        elif years < 100:
            return "⚡ MODERADO - Ataque posible con recursos"
        elif years < 1000000:
            return "✅ SEGURO - Ataque impracticable"
        else:
            return "🔒 MUY SEGURO - Resistente a fuerza bruta"
    
    @staticmethod
    def get_attack_info() -> dict:
        """Información sobre ataques de fuerza bruta."""
        return {
            'name': 'Ataque de Fuerza Bruta',
            'description': 'Probar todas las claves posibles hasta encontrar la correcta',
            'types': {
                'exhaustive': 'Probar todas las combinaciones posibles',
                'dictionary': 'Probar contraseñas de una lista común',
                'hybrid': 'Diccionario + variaciones (123, !, etc.)'
            },
            'defenses': [
                'Usar claves largas (16+ caracteres)',
                'Incluir mayúsculas, números y símbolos',
                'Implementar límites de intentos',
                'Usar funciones de derivación lentas (bcrypt, Argon2)'
            ],
            'tools': {
                'hashcat': 'Cracking de hashes con GPU',
                'john': 'John the Ripper - cracker versátil',
                'hydra': 'Ataques en línea a servicios'
            }
        }


class FrequencyAnalysis:
    """
    Análisis de frecuencia para romper cifrados de sustitución.
    """
    
    def __init__(self, language: str = 'spanish'):
        self.language = language
        self.expected_freqs = (SPANISH_FREQUENCIES if language == 'spanish' 
                               else ENGLISH_FREQUENCIES)
    
    def analyze(self, text: str) -> dict:
        """
        Analiza la frecuencia de letras en un texto.
        
        Args:
            text: Texto a analizar
            
        Returns:
            Análisis de frecuencias
        """
        letters = [c.lower() for c in text if c.isalpha()]
        total = len(letters)
        
        if total == 0:
            return {'error': 'No hay letras para analizar'}
        
        counts = Counter(letters)
        frequencies = {char: round((count / total) * 100, 2) 
                      for char, count in counts.items()}
        
        # Ordenar por frecuencia
        sorted_freqs = sorted(frequencies.items(), key=lambda x: x[1], reverse=True)
        
        # Sugerir mapeo basado en frecuencias
        expected_sorted = sorted(self.expected_freqs.items(), 
                                key=lambda x: x[1], reverse=True)
        
        suggested_mapping = {}
        for i, (cipher_char, _) in enumerate(sorted_freqs[:10]):
            if i < len(expected_sorted):
                suggested_mapping[cipher_char] = expected_sorted[i][0]
        
        return {
            'text_length': total,
            'frequencies': dict(sorted_freqs),
            'most_common': sorted_freqs[:5],
            'least_common': sorted_freqs[-5:],
            'suggested_mapping': suggested_mapping,
            'expected_most_common': expected_sorted[:5]
        }
    
    def break_substitution(self, ciphertext: str) -> dict:
        """
        Intenta romper un cifrado de sustitución usando análisis de frecuencia.
        
        Args:
            ciphertext: Texto cifrado
            
        Returns:
            Análisis y posible descifrado
        """
        analysis = self.analyze(ciphertext)
        
        if 'error' in analysis:
            return analysis
        
        # Aplicar mapeo sugerido
        mapping = analysis['suggested_mapping']
        partially_decrypted = ''
        
        for char in ciphertext:
            if char.lower() in mapping:
                replacement = mapping[char.lower()]
                partially_decrypted += replacement.upper() if char.isupper() else replacement
            else:
                partially_decrypted += char
        
        return {
            'original': ciphertext,
            'analysis': analysis,
            'partially_decrypted': partially_decrypted,
            'note': 'Este es un intento automático. El descifrado completo requiere ajuste manual.'
        }


def demo():
    """Demostración de ataques de fuerza bruta."""
    print("=== Demostración de Ataques de Fuerza Bruta ===\n")
    
    # 1. Ataque a César
    print("--- 1. Ataque a Cifrado César ---")
    from crypto_app.algorithms.caesar import CaesarCipher
    
    cipher = CaesarCipher(shift=7)
    original = "Este es un mensaje secreto muy importante"
    encrypted = cipher.encrypt(original)
    print(f"Texto cifrado: {encrypted}")
    
    attacker = BruteForceAttack()
    result = attacker.attack_caesar(encrypted)
    
    print(f"Mejor candidato (shift={result['best_guess']['shift']}): {result['best_guess']['decrypted']}")
    print(f"Intentos: {result['total_attempts']}")
    print(f"Tiempo: {result['time_seconds']} segundos")
    
    # 2. Estimación de tiempo
    print("\n--- 2. Estimación de Tiempo de Fuerza Bruta ---")
    
    # Contraseña de 4 caracteres (solo minúsculas)
    est1 = attacker.estimate_brute_force_time(4, 26)
    print(f"\n4 caracteres (a-z):")
    print(f"  Combinaciones: {est1['total_combinations']}")
    print(f"  Conclusión: {est1['conclusion']}")
    
    # Contraseña de 8 caracteres (alfanumérico)
    est2 = attacker.estimate_brute_force_time(8, 62)
    print(f"\n8 caracteres (a-z, A-Z, 0-9):")
    print(f"  Combinaciones: {est2['total_combinations']}")
    print(f"  Conclusión: {est2['conclusion']}")
    
    # Contraseña de 16 caracteres (todo)
    est3 = attacker.estimate_brute_force_time(16, 95)
    print(f"\n16 caracteres (todos imprimibles):")
    print(f"  Combinaciones: {est3['total_combinations']}")
    print(f"  Conclusión: {est3['conclusion']}")
    
    # 3. Análisis de frecuencia
    print("\n--- 3. Análisis de Frecuencia ---")
    analyzer = FrequencyAnalysis(language='spanish')
    analysis = analyzer.analyze(original)
    print(f"Letras más comunes: {analysis['most_common']}")
    print(f"Esperadas en español: {analysis['expected_most_common'][:5]}")


if __name__ == "__main__":
    demo()
