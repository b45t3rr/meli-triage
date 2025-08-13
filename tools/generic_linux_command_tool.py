#!/usr/bin/env python3
"""
Herramienta genérica para ejecutar comandos Linux básicos
Utilizada para testing de vulnerabilidades de forma segura
"""

import subprocess
import time
from typing import Dict, Any

class GenericLinuxCommandTool:
    """Tool para ejecutar comandos Linux genéricos como curl, nmap, etc."""
    
    def __init__(self):
        self.name = "generic_linux_command"
        self.description = "Ejecuta comandos Linux genéricos como curl, nmap, wget, etc. para testing de vulnerabilidades"
    
    def _run(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """Ejecuta un comando Linux y retorna el resultado"""
        try:
            # Validar que el comando sea seguro
            if not self._is_safe_command(command):
                return {
                    "success": False,
                    "error": "Comando no permitido por razones de seguridad",
                    "command": command
                }
            
            # Ejecutar comando
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "command": command,
                "timestamp": time.time()
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Comando excedió el timeout de {timeout} segundos",
                "command": command,
                "timestamp": time.time()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": command,
                "timestamp": time.time()
            }
    
    def _is_safe_command(self, command: str) -> bool:
        """Valida que el comando sea seguro para ejecutar"""
        # Lista de comandos permitidos
        allowed_commands = [
            'curl', 'nmap', 'wget', 'nc', 'netcat', 'ping', 'dig', 'nslookup',
            'telnet', 'ssh', 'scp', 'grep', 'awk', 'sed', 'cat', 'echo',
            'head', 'tail', 'wc', 'sort', 'uniq', 'cut', 'tr'
        ]
        
        # Comandos peligrosos que no se permiten (como palabras completas)
        dangerous_commands = [
            'rm', 'rmdir', 'mv', 'cp', 'chmod', 'chown', 'sudo', 'su',
            'passwd', 'useradd', 'userdel', 'groupadd', 'groupdel',
            'mount', 'umount', 'fdisk', 'mkfs', 'dd', 'format'
        ]
        
        # Dividir comando en palabras para análisis preciso
        command_words = command.lower().split()
        
        if not command_words:
            return False
        
        # Verificar que el primer comando sea permitido
        first_word = command_words[0]
        if first_word not in allowed_commands:
            return False
        
        # Verificar comandos peligrosos como palabras completas
        for dangerous in dangerous_commands:
            if dangerous in command_words:
                return False
        
        return True