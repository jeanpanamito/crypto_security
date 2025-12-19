"""
Vistas de la aplicación Django para demostración de criptografía.
"""

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json

from .algorithms import CaesarCipher, LFSRCipher, AESDemo, CipherX, SimpleRSA
from .authentication import HMACAuthenticator, DigitalSignature, MessageOriginVerifier
from .attacks import BruteForceAttack, FrequencyAnalysis, MITMSimulation


def index(request):
    """Vista principal - Dashboard."""
    return render(request, 'crypto_app/index.html')


def algorithms_view(request):
    """Vista de algoritmos criptográficos."""
    algorithms_info = {
        'caesar': {
            'name': 'Cifrado César',
            'type': 'Sustitución monoalfabética',
            'security': 'Muy débil - 26 claves posibles'
        },
        'lfsr': {
            'name': 'LFSR (Acarreo)',
            'type': 'Cifrado de flujo',
            'security': 'Débil si se conoce estructura'
        },
        'aes': AESDemo.get_algorithm_info(),
        'cipherx': CipherX.get_algorithm_info(),
        'simplersa': SimpleRSA.get_algorithm_info()
    }
    return render(request, 'crypto_app/algorithms.html', {'algorithms': algorithms_info})


def authentication_view(request):
    """Vista de autenticación de mensajes."""
    hmac_info = HMACAuthenticator.explain_hmac()
    signature_info = DigitalSignature.explain_digital_signature()
    comparison = MessageOriginVerifier.compare_methods()
    
    return render(request, 'crypto_app/authentication.html', {
        'hmac_info': hmac_info,
        'signature_info': signature_info,
        'comparison': comparison
    })


def attacks_view(request):
    """Vista de ataques criptográficos."""
    bf_info = BruteForceAttack.get_attack_info()
    mitm_info = MITMSimulation.get_mitm_info()
    
    return render(request, 'crypto_app/attacks.html', {
        'brute_force': bf_info,
        'mitm': mitm_info
    })


# ==================== API ENDPOINTS ====================

@csrf_exempt
@require_http_methods(["POST"])
def api_caesar(request):
    """API para cifrado César."""
    try:
        data = json.loads(request.body)
        action = data.get('action', 'encrypt')
        text = data.get('text', '')
        shift = int(data.get('shift', 3))
        
        cipher = CaesarCipher(shift=shift)
        
        if action == 'encrypt':
            result = cipher.encrypt(text)
        elif action == 'decrypt':
            result = cipher.decrypt(text)
        elif action == 'brute_force':
            result = cipher.brute_force_decrypt(text)
        elif action == 'frequency':
            result = cipher.frequency_analysis(text)
        else:
            return JsonResponse({'error': 'Acción no válida'}, status=400)
        
        return JsonResponse({
            'success': True,
            'action': action,
            'input': text,
            'shift': shift,
            'result': result
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_lfsr(request):
    """API para cifrado LFSR."""
    try:
        data = json.loads(request.body)
        action = data.get('action', 'encrypt')
        text = data.get('text', '')
        seed = int(data.get('seed', 0xACE1), 16) if isinstance(data.get('seed'), str) else int(data.get('seed', 0xACE1))
        
        cipher = LFSRCipher(seed=seed)
        
        if action == 'encrypt':
            ciphertext, keystream = cipher.encrypt(text)
            result = {
                'ciphertext': ciphertext,
                'keystream': keystream
            }
        elif action == 'decrypt':
            result = cipher.decrypt(text)
        elif action == 'visualize':
            result = cipher.visualize_process(text)
        else:
            return JsonResponse({'error': 'Acción no válida'}, status=400)
        
        return JsonResponse({
            'success': True,
            'action': action,
            'seed': hex(seed),
            'result': result
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_aes(request):
    """API para cifrado AES."""
    try:
        data = json.loads(request.body)
        action = data.get('action', 'encrypt')
        text = data.get('text', '')
        key = data.get('key', 'MiClaveSecreta16')
        mode = data.get('mode', 'CBC')
        
        # Asegurar que la clave tenga longitud válida
        key_bytes = key.encode('utf-8')
        if len(key_bytes) < 16:
            key_bytes = key_bytes.ljust(16, b'\x00')
        elif len(key_bytes) < 24:
            key_bytes = key_bytes[:16]
        elif len(key_bytes) < 32:
            key_bytes = key_bytes[:24]
        else:
            key_bytes = key_bytes[:32]
        
        aes = AESDemo(key=key_bytes, mode=mode)
        
        if action == 'encrypt':
            result = aes.encrypt(text)
        elif action == 'decrypt':
            iv = data.get('iv')
            nonce = data.get('nonce')
            ciphertext = data.get('ciphertext', text)
            result = aes.decrypt(ciphertext, iv, nonce)
        elif action == 'info':
            result = AESDemo.get_algorithm_info()
        elif action == 'subbytes':
            byte_val = int(data.get('byte', 0))
            result = aes.explain_subbytes(byte_val)
        else:
            return JsonResponse({'error': 'Acción no válida'}, status=400)
        
        return JsonResponse({
            'success': True,
            'action': action,
            'mode': mode,
            'result': result
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_custom_symmetric(request):
    """API para algoritmo simétrico propio (CipherX)."""
    try:
        data = json.loads(request.body)
        action = data.get('action', 'encrypt')
        text = data.get('text', '')
        key = data.get('key', 'ClaveXYZ')
        
        # Asegurar 8 bytes
        key_bytes = key.encode('utf-8')[:8].ljust(8, b'\x00')
        
        cipher = CipherX(key=key_bytes)
        
        if action == 'encrypt':
            result = cipher.encrypt(text)
        elif action == 'decrypt':
            result = cipher.decrypt(text)
        elif action == 'info':
            result = CipherX.get_algorithm_info()
        elif action == 'visualize':
            import struct
            block = struct.unpack('>Q', text[:8].encode('utf-8').ljust(8, b'\x00'))[0]
            result = cipher.visualize_round(block, 0)
        else:
            return JsonResponse({'error': 'Acción no válida'}, status=400)
        
        return JsonResponse({
            'success': True,
            'action': action,
            'result': result
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_custom_asymmetric(request):
    """API para algoritmo asimétrico propio (SimpleRSA)."""
    try:
        data = json.loads(request.body)
        action = data.get('action', 'generate')
        text = data.get('text', '')
        
        rsa = SimpleRSA(key_size='small')
        
        if action == 'generate':
            result = rsa.get_key_info()
        elif action == 'encrypt':
            ciphertext = rsa.encrypt(text)
            result = {
                'ciphertext': ciphertext,
                'key_info': rsa.get_key_info()
            }
        elif action == 'decrypt':
            ciphertext = data.get('ciphertext', [])
            result = rsa.decrypt(ciphertext)
        elif action == 'sign':
            signature, hash_val = rsa.sign(text)
            result = {
                'signature': signature,
                'hash': hash_val,
                'public_key': rsa.get_public_key()
            }
        elif action == 'verify':
            signature = int(data.get('signature', 0))
            result = rsa.verify(text, signature)
        elif action == 'visualize':
            char = text[0] if text else 'A'
            result = rsa.visualize_encryption(char)
        elif action == 'info':
            result = SimpleRSA.get_algorithm_info()
        else:
            return JsonResponse({'error': 'Acción no válida'}, status=400)
        
        return JsonResponse({
            'success': True,
            'action': action,
            'result': result
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_hmac(request):
    """API para HMAC."""
    try:
        data = json.loads(request.body)
        action = data.get('action', 'create')
        message = data.get('message', '')
        secret_key = data.get('key', 'clave_secreta')
        
        auth = HMACAuthenticator(secret_key)
        
        if action == 'create':
            mac = auth.create_mac(message)
            result = {
                'message': message,
                'mac': mac,
                'algorithm': 'SHA-256'
            }
        elif action == 'verify':
            mac = data.get('mac', '')
            is_valid = auth.verify_mac(message, mac)
            result = {
                'is_valid': is_valid,
                'message': message
            }
        elif action == 'authenticate':
            result = auth.create_authenticated_message(message)
        elif action == 'verify_full':
            auth_msg = {
                'message': message,
                'timestamp': data.get('timestamp'),
                'mac': data.get('mac')
            }
            result = auth.verify_authenticated_message(auth_msg)
        elif action == 'explain':
            result = HMACAuthenticator.explain_hmac()
        else:
            return JsonResponse({'error': 'Acción no válida'}, status=400)
        
        return JsonResponse({
            'success': True,
            'action': action,
            'result': result
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_signature(request):
    """API para firma digital."""
    try:
        data = json.loads(request.body)
        action = data.get('action', 'sign')
        message = data.get('message', '')
        
        signer = DigitalSignature(key_size=2048)
        
        if action == 'sign':
            signed = signer.create_signed_message(message)
            result = signed
        elif action == 'verify':
            signed_msg = {
                'message': message,
                'signature': data.get('signature'),
                'public_key': data.get('public_key')
            }
            result = signer.verify_signed_message(signed_msg)
        elif action == 'explain':
            result = DigitalSignature.explain_digital_signature()
        else:
            return JsonResponse({'error': 'Acción no válida'}, status=400)
        
        return JsonResponse({
            'success': True,
            'action': action,
            'result': result
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_brute_force(request):
    """API para ataques de fuerza bruta."""
    try:
        data = json.loads(request.body)
        action = data.get('action', 'caesar')
        ciphertext = data.get('ciphertext', '')
        
        attacker = BruteForceAttack()
        
        if action == 'caesar':
            known_word = data.get('known_word')
            result = attacker.attack_caesar(ciphertext, known_word)
        elif action == 'estimate':
            key_length = int(data.get('key_length', 8))
            charset_size = int(data.get('charset_size', 26))
            attempts_per_sec = int(data.get('attempts_per_sec', 1000000))
            result = attacker.estimate_brute_force_time(key_length, charset_size, attempts_per_sec)
        elif action == 'frequency':
            language = data.get('language', 'spanish')
            analyzer = FrequencyAnalysis(language)
            result = analyzer.analyze(ciphertext)
        elif action == 'info':
            result = BruteForceAttack.get_attack_info()
        else:
            return JsonResponse({'error': 'Acción no válida'}, status=400)
        
        return JsonResponse({
            'success': True,
            'action': action,
            'result': result
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_mitm(request):
    """API para simulación MITM."""
    try:
        data = json.loads(request.body)
        scenario = data.get('scenario', 'unencrypted')
        
        sim = MITMSimulation()
        
        if scenario == 'unencrypted':
            result = sim.scenario_unencrypted()
        elif scenario == 'diffie_hellman':
            result = sim.scenario_diffie_hellman_attack()
        elif scenario == 'with_signature':
            result = sim.scenario_with_signature()
        elif scenario == 'info':
            result = MITMSimulation.get_mitm_info()
        else:
            return JsonResponse({'error': 'Escenario no válido'}, status=400)
        
        return JsonResponse({
            'success': True,
            'scenario': scenario,
            'result': result
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_origin_verification(request):
    """API para demostración de verificación de origen."""
    try:
        data = json.loads(request.body)
        action = data.get('action', 'simulate')
        
        if action == 'simulate':
            result = MessageOriginVerifier.simulate_secure_channel()
        elif action == 'compare':
            result = MessageOriginVerifier.compare_methods()
        else:
            return JsonResponse({'error': 'Acción no válida'}, status=400)
        
        return JsonResponse({
            'success': True,
            'action': action,
            'result': result
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
