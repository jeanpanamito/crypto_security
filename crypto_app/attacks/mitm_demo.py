"""
Ataque Man-in-the-Middle (MITM)
================================
Demostración educativa de cómo funciona un ataque MITM y cómo prevenirlo.

El ataque MITM ocurre cuando un atacante se posiciona entre dos partes
que intentan comunicarse, interceptando y potencialmente alterando mensajes.

Escenarios demostrados:
1. MITM en comunicación sin cifrar
2. MITM en intercambio de claves Diffie-Hellman
3. Prevención con certificados/firma digital
"""

import random
import hashlib
from dataclasses import dataclass
from typing import Optional
from datetime import datetime


@dataclass
class Message:
    """Representa un mensaje en la comunicación."""
    sender: str
    receiver: str
    content: str
    encrypted: bool = False
    signature: Optional[str] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class Party:
    """Representa una parte en la comunicación (Alice, Bob, etc.)."""
    
    def __init__(self, name: str):
        self.name = name
        self.messages_sent = []
        self.messages_received = []
        self.shared_secret = None
        # Claves para Diffie-Hellman
        self.private_key = random.randint(1, 100)
        self.public_key = None
    
    def send_message(self, content: str, receiver: str) -> Message:
        """Envía un mensaje."""
        msg = Message(sender=self.name, receiver=receiver, content=content)
        self.messages_sent.append(msg)
        return msg
    
    def receive_message(self, message: Message):
        """Recibe un mensaje."""
        self.messages_received.append(message)
        return message.content
    
    def generate_dh_public_key(self, g: int, p: int) -> int:
        """Genera clave pública para Diffie-Hellman."""
        self.public_key = pow(g, self.private_key, p)
        return self.public_key
    
    def compute_shared_secret(self, other_public_key: int, p: int) -> int:
        """Calcula el secreto compartido con la otra parte."""
        self.shared_secret = pow(other_public_key, self.private_key, p)
        return self.shared_secret


class MITMAttacker:
    """
    Simulación de un atacante Man-in-the-Middle.
    """
    
    def __init__(self, name: str = "Eve"):
        self.name = name
        self.intercepted_messages = []
        self.modified_messages = []
        # Claves propias para DH attack
        self.private_key_alice = random.randint(1, 100)
        self.private_key_bob = random.randint(1, 100)
        self.shared_secret_alice = None
        self.shared_secret_bob = None
    
    def intercept(self, message: Message) -> Message:
        """Intercepta un mensaje sin modificarlo."""
        self.intercepted_messages.append({
            'original': message,
            'action': 'intercepted',
            'timestamp': datetime.now().isoformat()
        })
        return message
    
    def intercept_and_modify(self, message: Message, new_content: str) -> Message:
        """Intercepta y modifica un mensaje."""
        original_content = message.content
        modified_message = Message(
            sender=message.sender,
            receiver=message.receiver,
            content=new_content,
            encrypted=message.encrypted
        )
        
        self.modified_messages.append({
            'original_content': original_content,
            'modified_content': new_content,
            'from': message.sender,
            'to': message.receiver
        })
        
        return modified_message
    
    def dh_attack_intercept_alice(self, alice_public_key: int, g: int, p: int) -> int:
        """
        Intercepta la clave pública de Alice y envía la propia a Bob.
        """
        # Guardar para calcular secreto con Alice
        self.shared_secret_alice = pow(alice_public_key, self.private_key_alice, p)
        # Enviar nuestra clave a Bob (haciéndose pasar por Alice)
        return pow(g, self.private_key_bob, p)
    
    def dh_attack_intercept_bob(self, bob_public_key: int, g: int, p: int) -> int:
        """
        Intercepta la clave pública de Bob y envía la propia a Alice.
        """
        # Guardar para calcular secreto con Bob
        self.shared_secret_bob = pow(bob_public_key, self.private_key_bob, p)
        # Enviar nuestra clave a Alice (haciéndose pasar por Bob)
        return pow(g, self.private_key_alice, p)
    
    def get_intercepted_data(self) -> dict:
        """Retorna resumen de datos interceptados."""
        return {
            'total_intercepted': len(self.intercepted_messages),
            'total_modified': len(self.modified_messages),
            'messages': self.intercepted_messages,
            'modifications': self.modified_messages
        }


class MITMSimulation:
    """
    Simulación completa de escenarios MITM.
    """
    
    def __init__(self):
        self.alice = Party("Alice")
        self.bob = Party("Bob")
        self.eve = MITMAttacker("Eve")
    
    def scenario_unencrypted(self) -> dict:
        """
        Escenario 1: Comunicación sin cifrar.
        Eve puede leer y modificar todo.
        """
        steps = []
        
        # Paso 1: Alice envía mensaje
        msg1 = self.alice.send_message(
            "Hola Bob, mi número de tarjeta es 1234-5678-9012-3456",
            "Bob"
        )
        steps.append({
            'step': 1,
            'action': 'Alice envía mensaje',
            'content': msg1.content
        })
        
        # Paso 2: Eve intercepta
        intercepted = self.eve.intercept(msg1)
        steps.append({
            'step': 2,
            'action': 'Eve intercepta el mensaje',
            'sees': intercepted.content,
            'vulnerability': 'Sin cifrado, Eve lee todo'
        })
        
        # Paso 3: Eve modifica el mensaje
        modified = self.eve.intercept_and_modify(
            msg1,
            "Hola Bob, mi número de tarjeta es 9999-8888-7777-6666"
        )
        steps.append({
            'step': 3,
            'action': 'Eve modifica el mensaje',
            'original': msg1.content,
            'modified': modified.content
        })
        
        # Paso 4: Bob recibe mensaje modificado
        self.bob.receive_message(modified)
        steps.append({
            'step': 4,
            'action': 'Bob recibe mensaje modificado',
            'receives': modified.content,
            'thinks_from': 'Alice',
            'actually_from': 'Eve'
        })
        
        return {
            'scenario': 'Comunicación sin cifrar',
            'result': 'ATAQUE EXITOSO',
            'steps': steps,
            'conclusion': 'Sin cifrado, el atacante puede leer y modificar todo'
        }
    
    def scenario_diffie_hellman_attack(self) -> dict:
        """
        Escenario 2: Ataque MITM en Diffie-Hellman sin autenticación.
        """
        # Parámetros DH públicos
        p = 23  # Primo (pequeño para demo)
        g = 5   # Generador
        
        steps = []
        
        # Paso 1: Alice genera su clave pública
        alice_public = self.alice.generate_dh_public_key(g, p)
        steps.append({
            'step': 1,
            'action': 'Alice genera clave pública',
            'alice_private': self.alice.private_key,
            'alice_public': alice_public,
            'formula': f'g^a mod p = {g}^{self.alice.private_key} mod {p} = {alice_public}'
        })
        
        # Paso 2: Eve intercepta la clave de Alice
        eve_to_bob = self.eve.dh_attack_intercept_alice(alice_public, g, p)
        steps.append({
            'step': 2,
            'action': 'Eve intercepta clave de Alice, envía la suya a Bob',
            'alice_sent': alice_public,
            'eve_sends_to_bob': eve_to_bob,
            'eve_computes_secret_with_alice': self.eve.shared_secret_alice
        })
        
        # Paso 3: Bob genera su clave pública
        bob_public = self.bob.generate_dh_public_key(g, p)
        steps.append({
            'step': 3,
            'action': 'Bob genera clave pública',
            'bob_private': self.bob.private_key,
            'bob_public': bob_public
        })
        
        # Paso 4: Eve intercepta la clave de Bob
        eve_to_alice = self.eve.dh_attack_intercept_bob(bob_public, g, p)
        steps.append({
            'step': 4,
            'action': 'Eve intercepta clave de Bob, envía la suya a Alice',
            'bob_sent': bob_public,
            'eve_sends_to_alice': eve_to_alice,
            'eve_computes_secret_with_bob': self.eve.shared_secret_bob
        })
        
        # Paso 5: Alice y Bob calculan "su" secreto compartido
        alice_secret = self.alice.compute_shared_secret(eve_to_alice, p)
        bob_secret = self.bob.compute_shared_secret(eve_to_bob, p)
        
        steps.append({
            'step': 5,
            'action': 'Alice y Bob calculan secretos (diferentes!)',
            'alice_thinks_shared': alice_secret,
            'bob_thinks_shared': bob_secret,
            'eve_secret_with_alice': self.eve.shared_secret_alice,
            'eve_secret_with_bob': self.eve.shared_secret_bob,
            'problem': 'Alice y Bob tienen secretos diferentes, Eve conoce ambos'
        })
        
        return {
            'scenario': 'Ataque MITM en Diffie-Hellman',
            'result': 'ATAQUE EXITOSO',
            'steps': steps,
            'conclusion': 'Sin autenticación, DH es vulnerable a MITM',
            'solution': 'Usar certificados digitales para autenticar las claves públicas'
        }
    
    def scenario_with_signature(self) -> dict:
        """
        Escenario 3: Comunicación protegida con firma digital.
        Eve no puede modificar sin ser detectada.
        """
        steps = []
        
        # Simular firma con hash (simplificado)
        message = "Transferir $1000 a cuenta 12345"
        secret_key = "clave_secreta_alice"
        
        # Alice firma el mensaje
        signature = hashlib.sha256(
            (message + secret_key).encode()
        ).hexdigest()[:16]
        
        msg = Message(
            sender="Alice",
            receiver="Bob",
            content=message,
            signature=signature
        )
        
        steps.append({
            'step': 1,
            'action': 'Alice firma y envía mensaje',
            'message': message,
            'signature': signature
        })
        
        # Eve intenta modificar
        modified_content = "Transferir $10000 a cuenta 99999"
        modified_msg = Message(
            sender="Alice",
            receiver="Bob",
            content=modified_content,
            signature=signature  # Eve no puede recalcular la firma
        )
        
        steps.append({
            'step': 2,
            'action': 'Eve intenta modificar el mensaje',
            'original': message,
            'modified': modified_content,
            'keeps_signature': signature
        })
        
        # Bob verifica la firma
        expected_signature = hashlib.sha256(
            (modified_content + secret_key).encode()
        ).hexdigest()[:16]
        
        is_valid = (signature == expected_signature)
        
        steps.append({
            'step': 3,
            'action': 'Bob verifica la firma',
            'received_signature': signature,
            'expected_signature': expected_signature,
            'match': is_valid,
            'result': 'MODIFICACIÓN DETECTADA' if not is_valid else 'Válido'
        })
        
        return {
            'scenario': 'Comunicación con firma digital',
            'result': 'ATAQUE DETECTADO',
            'steps': steps,
            'conclusion': 'La firma digital previene modificaciones no detectadas'
        }
    
    @staticmethod
    def get_mitm_info() -> dict:
        """Información sobre ataques MITM."""
        return {
            'name': 'Man-in-the-Middle (MITM)',
            'description': 'Atacante intercepta comunicación entre dos partes',
            'techniques': {
                'arp_spoofing': 'Falsificar tablas ARP en red local',
                'dns_spoofing': 'Redirigir consultas DNS',
                'ssl_stripping': 'Degradar HTTPS a HTTP',
                'evil_twin': 'Crear punto de acceso WiFi falso'
            },
            'tools_kali': {
                'ettercap': 'Framework para MITM',
                'bettercap': 'Herramienta modular de ataques',
                'mitmproxy': 'Proxy para interceptar HTTPS',
                'wireshark': 'Análisis de tráfico de red',
                'arpspoof': 'Envenenamiento ARP'
            },
            'prevention': [
                'Usar HTTPS con certificados válidos',
                'Verificar huellas de certificados',
                'Usar VPN en redes no confiables',
                'Implementar certificate pinning',
                'Usar autenticación mutua'
            ]
        }


def demo():
    """Demostración de ataques MITM."""
    print("=== Demostración de Ataque Man-in-the-Middle ===\n")
    
    sim = MITMSimulation()
    
    # Escenario 1: Sin cifrado
    print("--- Escenario 1: Comunicación sin cifrar ---")
    result1 = sim.scenario_unencrypted()
    print(f"Resultado: {result1['result']}")
    for step in result1['steps']:
        print(f"  Paso {step['step']}: {step['action']}")
    print(f"Conclusión: {result1['conclusion']}\n")
    
    # Escenario 2: DH sin autenticación
    print("--- Escenario 2: Diffie-Hellman sin autenticación ---")
    sim2 = MITMSimulation()  # Nueva simulación
    result2 = sim2.scenario_diffie_hellman_attack()
    print(f"Resultado: {result2['result']}")
    print(f"Conclusión: {result2['conclusion']}")
    print(f"Solución: {result2['solution']}\n")
    
    # Escenario 3: Con firma digital
    print("--- Escenario 3: Con firma digital ---")
    result3 = sim.scenario_with_signature()
    print(f"Resultado: {result3['result']}")
    print(f"Conclusión: {result3['conclusion']}\n")
    
    # Información de herramientas
    print("--- Herramientas MITM en Kali Linux ---")
    info = MITMSimulation.get_mitm_info()
    for tool, desc in info['tools_kali'].items():
        print(f"  • {tool}: {desc}")


if __name__ == "__main__":
    demo()
