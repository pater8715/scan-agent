#!/usr/bin/env python3
"""
Scanner Module - Scan Agent v2.0
=================================
Módulo de ejecución de escaneos de vulnerabilidades con perfiles predefinidos.

Autor: Scan Agent Team
Versión: 2.0.0
"""

import subprocess
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import shlex


class ScanProfile:
    """Define un perfil de escaneo con comandos específicos"""
    
    def __init__(self, name: str, description: str, commands: List[Dict]):
        self.name = name
        self.description = description
        self.commands = commands
        self.requires_sudo = any(cmd.get('sudo', False) for cmd in commands)


class VulnerabilityScanner:
    """Ejecutor de escaneos de vulnerabilidades"""
    
    # Definición de perfiles de escaneo
    PROFILES = {
        'quick': ScanProfile(
            name='Quick Scan',
            description='Escaneo rápido de puertos y servicios básicos (5 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-Pn -sT --top-ports 100 {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 300,
                    'required': True
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
            ]
        ),
        
        'standard': ScanProfile(
            name='Standard Scan',
            description='Escaneo completo con detección de versiones y scripts básicos (15 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -sC -p- {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 900,
                    'required': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=vuln,safe {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 600,
                    'required': True
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-v http://{target}',
                    'output': 'curl_verbose_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
            ]
        ),
        
        'full': ScanProfile(
            name='Full Scan',
            description='Escaneo exhaustivo con todas las herramientas (30-60 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -sC -A -p- {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 1800,
                    'required': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=vuln,exploit,auth,discovery {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 1200,
                    'required': True
                },
                {
                    'tool': 'nikto',
                    'args': '-h http://{target} -Format txt',
                    'output': 'nikto_{target}.txt',
                    'timeout': 1800,
                    'required': False
                },
                {
                    'tool': 'gobuster',
                    'args': 'dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -q',
                    'output': 'gobuster_{target}.txt',
                    'timeout': 600,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-v http://{target}',
                    'output': 'curl_verbose_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
            ]
        ),
        
        'web': ScanProfile(
            name='Web Application Scan',
            description='Escaneo enfocado en aplicaciones web (20-30 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -p80,443,8080,8443 {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 300,
                    'required': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=http-enum,http-headers,http-methods,http-vuln* {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 600,
                    'required': True
                },
                {
                    'tool': 'nikto',
                    'args': '-h http://{target} -Format txt -Tuning 123456789ab',
                    'output': 'nikto_{target}.txt',
                    'timeout': 1800,
                    'required': False
                },
                {
                    'tool': 'gobuster',
                    'args': 'dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -q',
                    'output': 'gobuster_{target}.txt',
                    'timeout': 1200,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-v http://{target}',
                    'output': 'curl_verbose_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
            ]
        ),
        
        'stealth': ScanProfile(
            name='Stealth Scan',
            description='Escaneo sigiloso para evadir detección (30-45 min aprox, requiere sudo)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sS -sV -T2 -f {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 1800,
                    'required': True,
                    'sudo': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=vuln -T2 {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 1200,
                    'required': True,
                    'sudo': True
                }
            ]
        ),
        
        'network': ScanProfile(
            name='Network Infrastructure Scan',
            description='Escaneo de infraestructura de red completa (40 min aprox, requiere sudo)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -sC -O -p- {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 2400,
                    'required': True,
                    'sudo': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=default,discovery,version {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 1800,
                    'required': True
                }
            ]
        ),
        
        'compliance': ScanProfile(
            name='Compliance & Best Practices',
            description='Verificación de cumplimiento y mejores prácticas (10 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV --script=ssl-cert,ssl-enum-ciphers,http-security-headers {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 600,
                    'required': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=http-security-headers,http-headers,ssl-cert,ssl-enum-ciphers {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 600,
                    'required': True
                },
                {
                    'tool': 'curl',
                    'args': '-I https://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
            ]
        ),
        
        'api': ScanProfile(
            name='API Security Scan',
            description='Escaneo enfocado en APIs REST/SOAP (15 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -p80,443,8080,8443,3000,5000,8000 {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 300,
                    'required': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=http-methods,http-auth,http-cors {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 300,
                    'required': True
                },
                {
                    'tool': 'curl',
                    'args': '-I -H "Accept: application/json" http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
            ]
        ),

        'api-owasp': ScanProfile(
            name='OWASP API Security Top 10 (2023)',
            description='Verificación activa de las 10 categorías OWASP API Security Top 10 2023 (20-30 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -p80,443,8080,8443,3000,5000,8000,9000 {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 300,
                    'required': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=http-methods,http-auth,http-auth-finder,http-cors,http-security-headers {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 300,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-I -H "Accept: application/json" http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'gobuster',
                    'args': 'dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -q -t 20 -x json',
                    'output': 'gobuster_{target}.txt',
                    'timeout': 300,
                    'required': False
                }
            ]
        ),

        'zap-passive': ScanProfile(
            name='ZAP Passive Scan',
            description='Spider + escaneo pasivo con OWASP ZAP (sin tráfico activo de ataque) (10-15 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -p80,443,3000,8080,8081 {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 120,
                    'required': True
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
                # ZAP se ejecuta desde agent.py vía ZAPIntegration (no como subprocess)
            ]
        ),

        'zap-active': ScanProfile(
            name='ZAP Active Scan',
            description='Spider + escaneo pasivo + escaneo activo con OWASP ZAP (30-60 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -p80,443,3000,8080,8081 {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 120,
                    'required': True
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
                # ZAP active scan se ejecuta desde agent.py vía ZAPIntegration
            ]
        ),

        'lab': ScanProfile(
            name='Lab Environment Scan',
            description='Escaneo para entornos de práctica (Juice Shop en :3000, DVWA en :8081) - ideal para clases (10-15 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -p80,443,3000,8080,8081 {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 120,
                    'required': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=http-enum,http-headers,http-methods,http-auth-finder {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 180,
                    'required': False
                },
                {
                    'tool': 'nikto',
                    'args': '-h http://{target} -Format txt -timeout 3',
                    'output': 'nikto_{target}.txt',
                    'timeout': 600,
                    'required': False
                },
                {
                    'tool': 'gobuster',
                    'args': 'dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -q -t 20',
                    'output': 'gobuster_{target}.txt',
                    'timeout': 300,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-v http://{target}',
                    'output': 'curl_verbose_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
            ]
        )
    }
    
    def __init__(self, verbose: bool = False):
        """
        Inicializa el escáner de vulnerabilidades.
        
        Args:
            verbose: Mostrar información detallada
        """
        self.output_dir = None  # Se configurará en run_scan
        self.verbose = verbose
        self.results = {
            'started_at': None,
            'finished_at': None,
            'profile_used': None,
            'target': None,
            'commands_executed': [],
            'commands_failed': [],
            'outputs_generated': []
        }
    
    def check_tool_availability(self, tool: str) -> bool:
        """Verifica si una herramienta está disponible en el sistema"""
        try:
            result = subprocess.run(
                ['which', tool],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            available = result.returncode == 0
            
            if self.verbose:
                status = "✅ Disponible" if available else "❌ No encontrada"
                print(f"  [{tool}] {status}")
            
            return available
        except Exception as e:
            if self.verbose:
                print(f"  [{tool}] ❌ Error al verificar: {str(e)}")
            return False
    
    def check_all_tools(self, profile: ScanProfile) -> Dict[str, bool]:
        """Verifica disponibilidad de todas las herramientas del perfil"""
        if self.verbose:
            print(f"\n🔍 Verificando herramientas requeridas para '{profile.name}'...")
        
        tools = {}
        for cmd in profile.commands:
            tool = cmd['tool']
            if tool not in tools:
                tools[tool] = self.check_tool_availability(tool)
        
        return tools
    
    def execute_command(self, command: Dict, target: str) -> bool:
        """Ejecuta un comando individual del escaneo"""
        tool = command['tool']
        args = command['args'].format(target=target)
        output_file = os.path.join(
            self.output_dir,
            command['output'].format(target=target)
        )
        timeout = command.get('timeout', 300)
        use_sudo = command.get('sudo', False)
        
        # Construir comando completo
        full_command = f"{tool} {args}"
        if use_sudo:
            full_command = f"sudo {full_command}"
        
        if self.verbose:
            print(f"\n⚙️  Ejecutando: {full_command}")
            print(f"   Timeout: {timeout}s")
            print(f"   Salida: {output_file}")
        
        try:
            # Ejecutar comando
            start_time = datetime.now()
            
            process = subprocess.Popen(
                shlex.split(full_command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                returncode = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                if self.verbose:
                    print(f"   ⚠️  Comando excedió timeout de {timeout}s")
                return False
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Guardar salida
            with open(output_file, 'w') as f:
                f.write(stdout)
                if stderr:
                    f.write("\n\n=== STDERR ===\n")
                    f.write(stderr)
            
            # Registrar resultado
            self.results['commands_executed'].append({
                'tool': tool,
                'command': full_command,
                'output_file': output_file,
                'duration': duration,
                'returncode': returncode
            })
            
            self.results['outputs_generated'].append(output_file)
            
            if self.verbose:
                status = "✅" if returncode == 0 else "⚠️"
                print(f"   {status} Completado en {duration:.2f}s (código: {returncode})")
            
            return returncode == 0
            
        except FileNotFoundError:
            if self.verbose:
                print(f"   ❌ Herramienta '{tool}' no encontrada")
            self.results['commands_failed'].append({
                'tool': tool,
                'reason': 'Tool not found'
            })
            return False
            
        except Exception as e:
            if self.verbose:
                print(f"   ❌ Error: {str(e)}")
            self.results['commands_failed'].append({
                'tool': tool,
                'reason': str(e)
            })
            return False
    
    def run_scan(self, target: str, profile_name: str, output_dir: str = "./outputs") -> tuple:
        """Ejecuta un perfil de escaneo completo
        
        Args:
            target: IP o dominio objetivo
            profile_name: Nombre del perfil a ejecutar
            output_dir: Directorio donde guardar los archivos (default: ./outputs)
        
        Returns:
            tuple: (success: bool, generated_files: list)
        """
        
        # Configurar directorio de salida
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Validar perfil
        if profile_name not in self.PROFILES:
            raise ValueError(f"Perfil '{profile_name}' no existe. Perfiles disponibles: {', '.join(self.PROFILES.keys())}")
        
        profile = self.PROFILES[profile_name]
        
        # Inicializar resultados
        self.results['started_at'] = datetime.now()
        self.results['profile_used'] = profile_name
        self.results['target'] = target
        
        print("=" * 80)
        print(f"🎯 INICIANDO ESCANEO: {profile.name}")
        print("=" * 80)
        print(f"Target: {target}")
        print(f"Perfil: {profile.name}")
        print(f"Descripción: {profile.description}")
        print(f"Comandos a ejecutar: {len(profile.commands)}")
        print(f"Directorio de salida: {self.output_dir}")
        print("=" * 80)
        
        # Verificar herramientas
        tools_status = self.check_all_tools(profile)
        missing_required = []
        
        for cmd in profile.commands:
            tool = cmd['tool']
            if cmd.get('required', False) and not tools_status.get(tool, False):
                missing_required.append(tool)
        
        if missing_required:
            print(f"\n❌ ERROR: Faltan herramientas requeridas: {', '.join(missing_required)}")
            print("\nPara instalarlas:")
            for tool in missing_required:
                if tool == 'nmap':
                    print("  sudo apt-get install nmap")
                elif tool == 'nikto':
                    print("  sudo apt-get install nikto")
                elif tool == 'gobuster':
                    print("  sudo apt-get install gobuster")
            return self.results
        
        # Advertencia sobre sudo
        if profile.requires_sudo:
            print("\n⚠️  ADVERTENCIA: Este perfil requiere privilegios de sudo")
            print("   Algunos comandos necesitan permisos elevados")
        
        # Ejecutar comandos
        print(f"\n🚀 Iniciando escaneo...")
        
        successful = 0
        failed = 0
        
        for i, command in enumerate(profile.commands, 1):
            tool = command['tool']
            
            # Verificar si la herramienta está disponible
            if not tools_status.get(tool, False):
                if self.verbose:
                    print(f"\n[{i}/{len(profile.commands)}] ⏭️  Saltando '{tool}' (no disponible)")
                failed += 1
                continue
            
            if self.verbose:
                print(f"\n[{i}/{len(profile.commands)}] Ejecutando {tool}...")
            
            success = self.execute_command(command, target)
            
            if success:
                successful += 1
            else:
                failed += 1
                if command.get('required', False):
                    print(f"\n❌ ERROR CRÍTICO: Comando requerido falló: {tool}")
                    break
        
        # Finalizar
        self.results['finished_at'] = datetime.now()
        duration = (self.results['finished_at'] - self.results['started_at']).total_seconds()
        
        print("\n" + "=" * 80)
        print("✅ ESCANEO COMPLETADO")
        print("=" * 80)
        print(f"Duración total: {duration:.2f}s")
        print(f"Comandos exitosos: {successful}")
        print(f"Comandos fallidos: {failed}")
        print(f"Archivos generados: {len(self.results['outputs_generated'])}")
        print("\nArchivos de salida:")
        for output in self.results['outputs_generated']:
            print(f"  📄 {output}")
        print("=" * 80)
        
        # Retornar tupla (success, files)
        # Considerar exitoso si se generó al menos un archivo
        success = len(self.results['outputs_generated']) > 0 and successful > 0
        return success, self.results['outputs_generated']
    
    @staticmethod
    def list_profiles():
        """Lista todos los perfiles disponibles"""
        print("\n" + "=" * 80)
        print("📋 PERFILES DE ESCANEO DISPONIBLES")
        print("=" * 80)
        
        for name, profile in VulnerabilityScanner.PROFILES.items():
            print(f"\n🔹 {name.upper()}")
            print(f"   Nombre: {profile.name}")
            print(f"   Descripción: {profile.description}")
            print(f"   Comandos: {len(profile.commands)}")
            if profile.requires_sudo:
                print(f"   ⚠️  Requiere sudo")
            
            print(f"   Herramientas:")
            tools = list(set(cmd['tool'] for cmd in profile.commands))
            for tool in sorted(tools):
                print(f"      • {tool}")
        
        print("\n" + "=" * 80)
    
    @staticmethod
    def show_profile_details(profile_name: str):
        """Muestra detalles de un perfil específico"""
        if profile_name not in VulnerabilityScanner.PROFILES:
            print(f"❌ Perfil '{profile_name}' no existe")
            return
        
        profile = VulnerabilityScanner.PROFILES[profile_name]
        
        print("\n" + "=" * 80)
        print(f"📋 DETALLES DEL PERFIL: {profile.name.upper()}")
        print("=" * 80)
        print(f"Nombre: {profile.name}")
        print(f"Descripción: {profile.description}")
        print(f"Total de comandos: {len(profile.commands)}")
        if profile.requires_sudo:
            print("⚠️  Requiere privilegios de sudo")
        
        print("\n📝 COMANDOS A EJECUTAR:\n")
        
        for i, cmd in enumerate(profile.commands, 1):
            print(f"{i}. {cmd['tool'].upper()}")
            print(f"   Comando: {cmd['args']}")
            print(f"   Salida: {cmd['output']}")
            print(f"   Timeout: {cmd.get('timeout', 300)}s")
            print(f"   Requerido: {'Sí' if cmd.get('required', False) else 'No'}")
            if cmd.get('sudo', False):
                print(f"   Sudo: Sí")
            print()
        
        print("=" * 80)


if __name__ == '__main__':
    """Función principal para testing del scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Scanner de Vulnerabilidades - Módulo de Ejecución'
    )
    
    parser.add_argument(
        '--list-profiles',
        action='store_true',
        help='Lista todos los perfiles disponibles'
    )
    
    parser.add_argument(
        '--show-profile',
        type=str,
        metavar='PROFILE',
        help='Muestra detalles de un perfil específico'
    )
    
    parser.add_argument(
        '--target',
        type=str,
        metavar='IP',
        help='IP o dominio objetivo'
    )
    
    parser.add_argument(
        '--profile',
        type=str,
        choices=list(VulnerabilityScanner.PROFILES.keys()),
        default='standard',
        help='Perfil de escaneo a utilizar'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default='./outputs',
        help='Directorio para archivos de salida'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Modo verbose (más detalles)'
    )
    
    args = parser.parse_args()
    
    # Listar perfiles
    if args.list_profiles:
        VulnerabilityScanner.list_profiles()
        sys.exit(0)
    
    # Mostrar detalles de perfil
    if args.show_profile:
        VulnerabilityScanner.show_profile_details(args.show_profile)
        sys.exit(0)
    
    # Ejecutar escaneo
    if not args.target:
        print("❌ ERROR: Debe especificar un target con --target")
        parser.print_help()
        sys.exit(1)
    
    scanner = VulnerabilityScanner(
        output_dir=args.output_dir,
        verbose=args.verbose
    )
    
    scanner.run_scan(args.target, args.profile)
