"""
Módulo de Autenticación de Mensajes
====================================
Implementa métodos para verificar el origen e integridad de mensajes:

1. HMAC (Hash-based Message Authentication Code)
   - Verifica integridad y autenticidad con clave compartida
   
2. Firma Digital (RSA)
   - Verifica autenticidad sin compartir clave secreta

3. Verificación de Origen
   - Demuestra cómo saber si un mensaje viene de una fuente legítima
"""

import hmac
import hashlib
import json
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


class HMACAuthenticator:
    """
    Autenticación de mensajes usando HMAC.
    Permite verificar que un mensaje no fue alterado y proviene de alguien
    que conoce la clave secreta compartida.
    """
    
    def __init__(self, secret_key: str):
        """
        Inicializa el autenticador HMAC.
        
        Args:
            secret_key: Clave secreta compartida entre remitente y destinatario
        """
        self.secret_key = secret_key.encode('utf-8')
    
    def create_mac(self, message: str, algorithm: str = 'sha256') -> str:
        """
        Crea un código de autenticación (MAC) para un mensaje.
        
        Args:
            message: Mensaje a autenticar
            algorithm: Algoritmo hash a usar ('sha256', 'sha512', 'md5')
            
        Returns:
            MAC en formato hexadecimal
        """
        h = hmac.new(self.secret_key, message.encode('utf-8'), algorithm)
        return h.hexdigest()
    
    def verify_mac(self, message: str, mac: str, algorithm: str = 'sha256') -> bool:
        """
        Verifica si un MAC es válido para un mensaje.
        
        Args:
            message: Mensaje a verificar
            mac: MAC recibido
            algorithm: Algoritmo hash usado
            
        Returns:
            True si el MAC es válido
        """
        expected_mac = self.create_mac(message, algorithm)
        return hmac.compare_digest(expected_mac, mac)
    
    def create_authenticated_message(self, message: str) -> dict:
        """
        Crea un mensaje autenticado con timestamp y MAC.
        
        Args:
            message: Mensaje a autenticar
            
        Returns:
            Diccionario con mensaje, timestamp y MAC
        """
        timestamp = datetime.now().isoformat()
        full_data = f"{message}|{timestamp}"
        mac = self.create_mac(full_data)
        
        return {
            'message': message,
            'timestamp': timestamp,
            'mac': mac
        }
    
    def verify_authenticated_message(self, auth_message: dict) -> dict:
        """
        Verifica un mensaje autenticado.
        
        Args:
            auth_message: Diccionario con mensaje, timestamp y MAC
            
        Returns:
            Diccionario con resultado de verificación
        """
        full_data = f"{auth_message['message']}|{auth_message['timestamp']}"
        is_valid = self.verify_mac(full_data, auth_message['mac'])
        
        return {
            'is_valid': is_valid,
            'message': auth_message['message'],
            'timestamp': auth_message['timestamp'],
            'verification_time': datetime.now().isoformat()
        }
    
    @staticmethod
    def explain_hmac() -> dict:
        """Explica cómo funciona HMAC."""
        return {
            'name': 'HMAC - Hash-based Message Authentication Code',
            'purpose': 'Verificar integridad y autenticidad de mensajes',
            'how_it_works': [
                '1. El remitente y destinatario comparten una clave secreta',
                '2. El remitente calcula HMAC(clave, mensaje)',
                '3. Envía el mensaje junto con el HMAC',
                '4. El destinatario recalcula el HMAC con su clave',
                '5. Si coinciden, el mensaje es auténtico e íntegro'
            ],
            'formula': 'HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))',
            'security': {
                'protects_against': ['Modificación de mensaje', 'Suplantación de identidad'],
                'requires': 'Canal seguro para compartir la clave'
            }
        }


class DigitalSignature:
    """
    Firma digital usando RSA.
    Permite verificar autenticidad sin compartir clave secreta.
    """
    
    def __init__(self, key_size: int = 2048):
        """
        Genera un par de claves RSA.
        
        Args:
            key_size: Tamaño de clave en bits
        """
        self.key = RSA.generate(key_size)
        self.public_key = self.key.publickey()
    
    def sign(self, message: str) -> bytes:
        """
        Firma un mensaje con la clave privada.
        
        Args:
            message: Mensaje a firmar
            
        Returns:
            Firma digital
        """
        h = SHA256.new(message.encode('utf-8'))
        signature = pkcs1_15.new(self.key).sign(h)
        return signature
    
    def verify(self, message: str, signature: bytes, public_key=None) -> bool:
        """
        Verifica una firma digital.
        
        Args:
            message: Mensaje original
            signature: Firma a verificar
            public_key: Clave pública (usa la propia si no se especifica)
            
        Returns:
            True si la firma es válida
        """
        if public_key is None:
            public_key = self.public_key
        
        h = SHA256.new(message.encode('utf-8'))
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    
    def export_public_key(self) -> str:
        """Exporta la clave pública en formato PEM."""
        return self.public_key.export_key().decode('utf-8')
    
    def export_private_key(self) -> str:
        """Exporta la clave privada en formato PEM."""
        return self.key.export_key().decode('utf-8')
    
    @staticmethod
    def import_public_key(pem_key: str):
        """Importa una clave pública desde formato PEM."""
        return RSA.import_key(pem_key.encode('utf-8'))
    
    def create_signed_message(self, message: str) -> dict:
        """
        Crea un mensaje con firma digital.
        
        Args:
            message: Mensaje a firmar
            
        Returns:
            Diccionario con mensaje, firma y clave pública
        """
        signature = self.sign(message)
        
        return {
            'message': message,
            'signature': signature.hex(),
            'public_key': self.export_public_key(),
            'timestamp': datetime.now().isoformat(),
            'algorithm': 'RSA-SHA256'
        }
    
    def verify_signed_message(self, signed_msg: dict) -> dict:
        """
        Verifica un mensaje firmado.
        
        Args:
            signed_msg: Diccionario con mensaje firmado
            
        Returns:
            Resultado de la verificación
        """
        public_key = self.import_public_key(signed_msg['public_key'])
        signature = bytes.fromhex(signed_msg['signature'])
        is_valid = self.verify(signed_msg['message'], signature, public_key)
        
        return {
            'is_valid': is_valid,
            'message': signed_msg['message'],
            'signer_verified': is_valid,
            'verification_time': datetime.now().isoformat()
        }
    
    @staticmethod
    def explain_digital_signature() -> dict:
        """Explica cómo funcionan las firmas digitales."""
        return {
            'name': 'Firma Digital RSA',
            'purpose': 'Verificar autenticidad y no repudio',
            'how_it_works': [
                '1. El remitente genera par de claves (pública/privada)',
                '2. Calcula hash del mensaje: h = SHA256(mensaje)',
                '3. Firma el hash con clave privada: firma = h^d mod n',
                '4. Envía mensaje + firma + clave pública',
                '5. El destinatario verifica: h == firma^e mod n'
            ],
            'advantages': [
                'No requiere compartir secretos',
                'Proporciona no repudio',
                'Cualquiera puede verificar con la clave pública'
            ],
            'use_cases': ['Contratos digitales', 'Certificados SSL', 'Actualizaciones de software']
        }


class MessageOriginVerifier:
    """
    Demostración de verificación de origen de mensajes.
    Combina HMAC y firma digital para mostrar diferentes escenarios.
    """
    
    @staticmethod
    def simulate_secure_channel():
        """
        Simula una comunicación segura entre Alice y Bob.
        
        Returns:
            Diccionario con la simulación paso a paso
        """
        simulation = {
            'scenario': 'Alice envía un mensaje secreto a Bob',
            'steps': []
        }
        
        # Paso 1: Establecer clave compartida
        shared_secret = "clave_secreta_compartida_123"
        simulation['steps'].append({
            'step': 1,
            'action': 'Establecer clave compartida',
            'description': 'Alice y Bob acuerdan una clave secreta por un canal seguro',
            'shared_secret': shared_secret[:10] + '...'
        })
        
        # Paso 2: Alice prepara el mensaje
        message = "Transferir $1000 a la cuenta 12345"
        alice_auth = HMACAuthenticator(shared_secret)
        auth_msg = alice_auth.create_authenticated_message(message)
        
        simulation['steps'].append({
            'step': 2,
            'action': 'Alice crea mensaje autenticado',
            'message': message,
            'mac': auth_msg['mac'][:16] + '...',
            'timestamp': auth_msg['timestamp']
        })
        
        # Paso 3: Bob verifica el mensaje
        bob_auth = HMACAuthenticator(shared_secret)
        verification = bob_auth.verify_authenticated_message(auth_msg)
        
        simulation['steps'].append({
            'step': 3,
            'action': 'Bob verifica el mensaje',
            'is_authentic': verification['is_valid'],
            'can_trust': 'Sí, porque solo Alice conoce la clave'
        })
        
        # Paso 4: Simular ataque (mensaje alterado)
        tampered_msg = auth_msg.copy()
        tampered_msg['message'] = "Transferir $10000 a la cuenta 99999"
        tampered_verification = bob_auth.verify_authenticated_message(tampered_msg)
        
        simulation['steps'].append({
            'step': 4,
            'action': 'Simulación de ataque (mensaje alterado)',
            'tampered_message': tampered_msg['message'],
            'detection': 'DETECTADO - MAC no coincide',
            'is_authentic': tampered_verification['is_valid']
        })
        
        return simulation
    
    @staticmethod
    def compare_methods() -> dict:
        """Compara HMAC vs Firma Digital."""
        return {
            'hmac': {
                'name': 'HMAC',
                'type': 'Simétrico',
                'key_sharing': 'Requiere clave compartida',
                'speed': 'Muy rápido',
                'non_repudiation': 'No proporciona',
                'use_case': 'Comunicación entre dos partes de confianza'
            },
            'digital_signature': {
                'name': 'Firma Digital',
                'type': 'Asimétrico',
                'key_sharing': 'No requiere compartir secretos',
                'speed': 'Más lento',
                'non_repudiation': 'Sí proporciona',
                'use_case': 'Documentos legales, verificación pública'
            }
        }


def demo():
    """Demostración de autenticación de mensajes."""
    print("=== Demostración de Autenticación de Mensajes ===\n")
    
    # HMAC Demo
    print("--- 1. HMAC (Hash-based Message Authentication Code) ---")
    hmac_auth = HMACAuthenticator("mi_clave_secreta")
    
    mensaje = "Este es un mensaje importante"
    mac = hmac_auth.create_mac(mensaje)
    print(f"Mensaje: {mensaje}")
    print(f"HMAC: {mac}")
    
    # Verificación correcta
    is_valid = hmac_auth.verify_mac(mensaje, mac)
    print(f"¿HMAC válido?: {is_valid}")
    
    # Verificación con mensaje alterado
    is_valid_fake = hmac_auth.verify_mac(mensaje + "!", mac)
    print(f"¿HMAC válido (mensaje alterado)?: {is_valid_fake}")
    
    # Firma Digital Demo
    print("\n--- 2. Firma Digital RSA ---")
    signer = DigitalSignature(key_size=2048)
    
    mensaje = "Documento legal importante"
    signed = signer.create_signed_message(mensaje)
    print(f"Mensaje: {signed['message']}")
    print(f"Firma (primeros 32 chars): {signed['signature'][:32]}...")
    
    # Verificar
    result = signer.verify_signed_message(signed)
    print(f"¿Firma válida?: {result['is_valid']}")
    
    # Simulación de canal seguro
    print("\n--- 3. Simulación de Comunicación Segura ---")
    simulation = MessageOriginVerifier.simulate_secure_channel()
    print(f"Escenario: {simulation['scenario']}")
    for step in simulation['steps']:
        print(f"\n  Paso {step['step']}: {step['action']}")
        for k, v in step.items():
            if k not in ['step', 'action']:
                print(f"    - {k}: {v}")


if __name__ == "__main__":
    demo()
