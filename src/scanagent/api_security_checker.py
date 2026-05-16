#!/usr/bin/env python3
"""
API Security Checker - Scan Agent
===================================
Verificación activa de las vulnerabilidades OWASP API Security Top 10 (2023).

API1:2023  — Broken Object Level Authorization (BOLA/IDOR)
API2:2023  — Broken Authentication
API3:2023  — Broken Object Property Level Authorization
API4:2023  — Unrestricted Resource Consumption
API5:2023  — Broken Function Level Authorization
API6:2023  — Unrestricted Access to Sensitive Business Flows
API7:2023  — Server Side Request Forgery (SSRF)
API8:2023  — Security Misconfiguration
API9:2023  — Improper Inventory Management
API10:2023 — Unsafe Consumption of APIs

Uso: solo en sistemas propios o con autorización explícita.
Autor: Scan Agent Team
Versión: 1.0.0
"""

import json
import ssl
import time
import socket
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path


class APISecurityChecker:
    """
    Verifica activamente las 10 categorías del OWASP API Security Top 10 (2023).
    Cada check genera hallazgos estructurados con severidad, evidencia y recomendación.
    """

    OWASP_API_TOP_10 = {
        "API1:2023": {
            "nombre": "Broken Object Level Authorization",
            "descripcion": (
                "Las APIs exponen endpoints que manejan identificadores de objetos, "
                "creando una superficie de ataque amplia para acceso no autorizado a datos de otros usuarios."
            ),
            "cvss_base": 9.8,
            "owasp_web_eq": "A01:2021"
        },
        "API2:2023": {
            "nombre": "Broken Authentication",
            "descripcion": (
                "Mecanismos de autenticación implementados incorrectamente permiten comprometer tokens "
                "o explotar fallas en la implementación del flujo de autenticación."
            ),
            "cvss_base": 8.1,
            "owasp_web_eq": "A07:2021"
        },
        "API3:2023": {
            "nombre": "Broken Object Property Level Authorization",
            "descripcion": (
                "Falta de validación de autorización a nivel de propiedad permite leer o modificar "
                "propiedades sensibles (excessive data exposure, mass assignment)."
            ),
            "cvss_base": 8.1,
            "owasp_web_eq": "A01:2021"
        },
        "API4:2023": {
            "nombre": "Unrestricted Resource Consumption",
            "descripcion": (
                "Sin límites de tasa adecuados, los atacantes pueden agotar recursos del servidor, "
                "realizar fuerza bruta o causar denegación de servicio."
            ),
            "cvss_base": 5.3,
            "owasp_web_eq": "A04:2021"
        },
        "API5:2023": {
            "nombre": "Broken Function Level Authorization",
            "descripcion": (
                "Políticas de autorización poco claras permiten acceder a funciones "
                "administrativas o privilegiadas sin los permisos adecuados."
            ),
            "cvss_base": 8.1,
            "owasp_web_eq": "A01:2021"
        },
        "API6:2023": {
            "nombre": "Unrestricted Access to Sensitive Business Flows",
            "descripcion": (
                "Endpoints de negocio expuestos sin restricciones permiten automatizar acciones "
                "que deberían ser manuales (compras masivas, fraude, spam)."
            ),
            "cvss_base": 5.3,
            "owasp_web_eq": "A04:2021"
        },
        "API7:2023": {
            "nombre": "Server Side Request Forgery",
            "descripcion": (
                "La API obtiene recursos remotos sin validar la URL del usuario, "
                "permitiendo forzar al servidor a conectarse a servicios internos."
            ),
            "cvss_base": 7.5,
            "owasp_web_eq": "A10:2021"
        },
        "API8:2023": {
            "nombre": "Security Misconfiguration",
            "descripcion": (
                "Configuraciones incorrectas: CORS permisivo, headers faltantes, "
                "mensajes de error verbosos, documentación expuesta públicamente."
            ),
            "cvss_base": 6.5,
            "owasp_web_eq": "A05:2021"
        },
        "API9:2023": {
            "nombre": "Improper Inventory Management",
            "descripcion": (
                "Versiones antiguas o de debug de APIs expuestas en producción, "
                "sin inventario actualizado de endpoints y versiones."
            ),
            "cvss_base": 5.3,
            "owasp_web_eq": "A06:2021"
        },
        "API10:2023": {
            "nombre": "Unsafe Consumption of APIs",
            "descripcion": (
                "Los desarrolladores confían en datos de APIs de terceros sin validación, "
                "lo que puede introducir vulnerabilidades por datos maliciosos externos."
            ),
            "cvss_base": 6.5,
            "owasp_web_eq": "A08:2021"
        }
    }

    COMMON_API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/v1", "/v2", "/v3",
        "/rest", "/rest/v1",
        "/swagger", "/swagger-ui", "/swagger-ui.html",
        "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml",
        "/api-docs", "/api-docs.json",
        "/docs", "/doc", "/redoc",
        "/graphql", "/graphiql",
        "/health", "/healthz", "/ping", "/status",
        "/metrics",
        "/actuator", "/actuator/health", "/actuator/env",
        "/api/users", "/api/user", "/api/accounts",
        "/api/admin", "/api/administration",
        "/api/debug", "/api/test", "/api/internal",
        "/api/config", "/api/settings",
        "/api/products", "/api/items", "/api/orders",
    ]

    def __init__(
        self,
        target: str,
        port: int = 80,
        use_https: bool = False,
        api_prefix: str = "",
        timeout: int = 8,
        verbose: bool = False
    ):
        self.target = target
        self.port = port
        self.use_https = use_https
        self.scheme = "https" if use_https else "http"
        self.api_prefix = api_prefix.rstrip("/")
        self.timeout = timeout
        self.verbose = verbose
        self.findings: List[Dict] = []
        self.base_url = f"{self.scheme}://{target}:{port}"
        self.discovered_paths: List[Dict] = []
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    # =========================================================================
    # Orquestador principal
    # =========================================================================

    def run_all_checks(self) -> List[Dict[str, Any]]:
        """Ejecuta todos los checks OWASP API Security Top 10 (2023)."""
        print("\n" + "=" * 70)
        print("OWASP API SECURITY TOP 10 (2023) — ANÁLISIS ACTIVO")
        print("=" * 70)
        print(f"Target   : {self.base_url}")
        print(f"Timestamp: {datetime.now().isoformat()}")
        print("=" * 70)

        self._discover_api_paths()

        checks = [
            ("API1:2023", "Broken Object Level Authorization",   self.check_api1_bola),
            ("API2:2023", "Broken Authentication",               self.check_api2_broken_auth),
            ("API3:2023", "Broken Object Property Level Auth",   self.check_api3_broken_property),
            ("API4:2023", "Unrestricted Resource Consumption",   self.check_api4_rate_limiting),
            ("API5:2023", "Broken Function Level Authorization", self.check_api5_function_auth),
            ("API6:2023", "Unrestricted Access to Sensitive Flows", self.check_api6_sensitive_flows),
            ("API7:2023", "Server Side Request Forgery",         self.check_api7_ssrf),
            ("API8:2023", "Security Misconfiguration",           self.check_api8_misconfiguration),
            ("API9:2023", "Improper Inventory Management",       self.check_api9_inventory),
            ("API10:2023", "Unsafe Consumption of APIs",         self.check_api10_unsafe_consumption),
        ]

        for check_id, check_name, check_fn in checks:
            print(f"\n[{check_id}] {check_name}")
            try:
                results = check_fn()
                self.findings.extend(results)
                vulnerable = [r for r in results if r.get("estado") in ("vulnerable", "posiblemente_vulnerable")]
                if vulnerable:
                    print(f"  [!] {len(vulnerable)} hallazgo(s) encontrado(s)")
                else:
                    print("  [OK] Sin hallazgos detectados")
            except Exception as e:
                if self.verbose:
                    print(f"  [ERROR] {check_id}: {e}")

        total_v = sum(1 for f in self.findings if f["estado"] == "vulnerable")
        total_p = sum(1 for f in self.findings if f["estado"] == "posiblemente_vulnerable")
        print("\n" + "=" * 70)
        print(f"RESUMEN: {total_v} vulnerables | {total_p} posiblemente vulnerables | {len(self.findings)} checks")
        print("=" * 70)
        return self.findings

    # =========================================================================
    # HTTP helper
    # =========================================================================

    def _http_request(
        self,
        method: str,
        path: str,
        headers: Optional[Dict] = None,
        body: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Realiza una petición HTTP y devuelve status, headers, body."""
        url = f"{self.base_url}{path}"
        result: Dict[str, Any] = {
            "url": url, "method": method,
            "status_code": None, "headers": {},
            "body": "", "error": None, "response_time_ms": 0
        }
        start = time.time()
        try:
            req_headers = {
                "User-Agent": "ScanAgent/3.0 (Security Audit; Educational)",
                "Accept": "application/json, text/html, */*",
            }
            if headers:
                req_headers.update(headers)
            data = body.encode("utf-8") if body else None
            req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                result["status_code"] = resp.status
                result["headers"] = dict(resp.headers)
                result["body"] = resp.read(4096).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            result["status_code"] = e.code
            result["headers"] = dict(e.headers) if e.headers else {}
            try:
                result["body"] = e.read(2048).decode("utf-8", errors="replace")
            except Exception:
                pass
        except urllib.error.URLError as e:
            result["error"] = str(e.reason)
        except socket.timeout:
            result["error"] = "timeout"
        except Exception as e:
            result["error"] = str(e)
        finally:
            result["response_time_ms"] = int((time.time() - start) * 1000)
        return result

    def _discover_api_paths(self) -> None:
        """Descubre paths de API activos en el target."""
        print("\n[*] Descubriendo endpoints de API...")
        found = []
        for path in self.COMMON_API_PATHS:
            r = self._http_request("GET", path)
            if r["status_code"] and r["status_code"] not in (404, 500, 502, 503):
                found.append({
                    "path": path,
                    "status": r["status_code"],
                    "content_type": r["headers"].get("Content-Type", "")
                })
                if self.verbose:
                    print(f"  [{r['status_code']}] {path}")
        self.discovered_paths = found
        print(f"  Endpoints activos encontrados: {len(found)}")

    # =========================================================================
    # API1:2023 — Broken Object Level Authorization (BOLA/IDOR)
    # =========================================================================

    def check_api1_bola(self) -> List[Dict]:
        findings = []
        # Endpoints que manejan recursos individuales por ID
        candidate_bases = list({
            p["path"] for p in self.discovered_paths
            if any(w in p["path"].lower() for w in ["user", "account", "order", "product", "item"])
        } | {"/api/users", "/api/user", "/api/accounts", "/api/orders", "/api/products"})

        for base_path in candidate_bases[:6]:
            responses = {}
            for obj_id in [1, 2, 3, 100]:
                r = self._http_request("GET", f"{base_path}/{obj_id}")
                if r["status_code"]:
                    responses[obj_id] = r

            accessible = {k: v for k, v in responses.items() if v["status_code"] == 200}
            if accessible:
                bodies = [v["body"][:200] for v in accessible.values()]
                responses_differ = len(set(bodies)) > 1
                estado = "vulnerable" if responses_differ else "posiblemente_vulnerable"
                findings.append(self._make_finding(
                    "API1:2023",
                    f"BOLA/IDOR — Acceso sin autenticación a {base_path}/{{id}}",
                    (
                        f"'{base_path}/{{id}}' responde HTTP 200 sin autenticación para IDs: {list(accessible.keys())}. "
                        + ("Las respuestas difieren por ID — posible exposición de datos de otros usuarios."
                           if responses_differ else "Las respuestas son iguales para todos los IDs probados.")
                    ),
                    estado,
                    "critica" if responses_differ else "alta",
                    {"endpoint": f"{base_path}/{{id}}", "ids_accesibles": list(accessible.keys()),
                     "respuestas_difieren": responses_differ},
                    (
                        "Verificar en cada solicitud que el usuario autenticado sea propietario del objeto. "
                        "Usar UUIDs en lugar de IDs secuenciales para dificultar la enumeración. "
                        "Implementar autorización a nivel de objeto en cada endpoint."
                    )
                ))

        # Verificar listado masivo sin auth
        r_list = self._http_request("GET", "/api/users")
        if r_list["status_code"] == 200 and not findings:
            findings.append(self._make_finding(
                "API1:2023",
                "BOLA — Listado de usuarios sin autenticación",
                "GET /api/users devuelve HTTP 200 sin requerir autenticación. Expone datos de todos los usuarios.",
                "posiblemente_vulnerable", "alta",
                {"endpoint": "/api/users", "status_code": 200},
                "Proteger todos los endpoints de recursos con autenticación obligatoria."
            ))
        return findings

    # =========================================================================
    # API2:2023 — Broken Authentication
    # =========================================================================

    def check_api2_broken_auth(self) -> List[Dict]:
        findings = []

        # JWT con algoritmo 'none' (técnica clásica de bypass)
        none_jwt = (
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0."
        )
        r_jwt = self._http_request("GET", "/api/users", headers={"Authorization": f"Bearer {none_jwt}"})
        if r_jwt["status_code"] == 200:
            findings.append(self._make_finding(
                "API2:2023",
                "JWT Algorithm None — Autenticación omitida",
                "El servidor acepta JWT firmados con alg=none, permitiendo forjar tokens sin clave secreta.",
                "vulnerable", "critica",
                {"jwt_alg": "none", "status_code": 200},
                (
                    "Rechazar explícitamente tokens con alg=none en el servidor. "
                    "Usar librerías de JWT actualizadas con allowlist de algoritmos permitidos (RS256, ES256). "
                    "Nunca confiar en el campo 'alg' del header del token."
                )
            ))

        # Endpoints protegidos accesibles sin token
        protected_paths = [p["path"] for p in self.discovered_paths
                          if p["status"] == 200 and any(
                              w in p["path"].lower() for w in ["user", "account", "profile", "admin", "me"]
                          )]
        for path in protected_paths[:4]:
            r = self._http_request("GET", path, headers={"Authorization": ""})
            if r["status_code"] == 200:
                findings.append(self._make_finding(
                    "API2:2023",
                    f"Autenticación no requerida en {path}",
                    f"'{path}' devuelve HTTP 200 con header Authorization vacío.",
                    "posiblemente_vulnerable", "alta",
                    {"path": path, "status_code": 200},
                    "Implementar middleware global de autenticación. Ningún endpoint de datos debe funcionar sin token válido."
                ))

        # Fuerza bruta sin bloqueo en endpoints de login
        login_paths = ["/api/login", "/api/auth", "/api/auth/login", "/api/v1/login", "/rest/user/login"]
        for login_path in login_paths:
            responses_codes = []
            for _ in range(6):
                r = self._http_request(
                    "POST", login_path,
                    headers={"Content-Type": "application/json"},
                    body='{"email":"test@test.com","password":"wrong_pass_scan_test"}'
                )
                if r["status_code"]:
                    responses_codes.append(r["status_code"])
            if responses_codes and 429 not in responses_codes:
                findings.append(self._make_finding(
                    "API2:2023",
                    f"Sin protección contra fuerza bruta en {login_path}",
                    (
                        f"'{login_path}' no retorna HTTP 429 tras 6 intentos fallidos consecutivos. "
                        f"Respuestas obtenidas: {responses_codes}."
                    ),
                    "posiblemente_vulnerable", "alta",
                    {"path": login_path, "intentos": 6, "respuestas": responses_codes},
                    (
                        "Bloquear la cuenta o retornar HTTP 429 con Retry-After tras N intentos fallidos. "
                        "Implementar CAPTCHA para usuarios no verificados. "
                        "Considerar OAuth2/OpenID Connect para delegar la autenticación."
                    )
                ))
                break
        return findings

    # =========================================================================
    # API3:2023 — Broken Object Property Level Authorization
    # =========================================================================

    def check_api3_broken_property(self) -> List[Dict]:
        findings = []
        sensitive_fields = [
            "password", "passwd", "hash", "salt", "secret",
            "token", "credit_card", "ssn", "pin", "private_key", "api_key"
        ]

        # Exposición de campos sensibles en respuestas
        for path in ["/api/users/1", "/api/user/1", "/api/accounts/1", "/api/me"]:
            r = self._http_request("GET", path)
            if r["status_code"] == 200 and r["body"]:
                exposed = [f for f in sensitive_fields if f in r["body"].lower()]
                if exposed:
                    findings.append(self._make_finding(
                        "API3:2023",
                        f"Exposición de propiedades sensibles en {path}",
                        (
                            f"La respuesta de '{path}' contiene campos potencialmente sensibles: {exposed}. "
                            "Esto puede indicar exposición excesiva de datos."
                        ),
                        "posiblemente_vulnerable", "alta",
                        {"path": path, "campos_detectados": exposed, "fragmento": r["body"][:300]},
                        (
                            "Devolver solo los campos necesarios para cada operación (response shaping). "
                            "Usar DTOs con allowlist explícita de campos. "
                            "Nunca exponer hashes de contraseñas ni tokens internos."
                        )
                    ))

        # Mass Assignment — enviar campos privilegiados en PUT/PATCH
        malicious_payload = json.dumps({
            "role": "admin", "is_admin": True,
            "permissions": ["read", "write", "admin"], "balance": 999999
        })
        for path in ["/api/users/1", "/api/user/1", "/api/profile"]:
            for method in ["PUT", "PATCH"]:
                r = self._http_request(
                    method, path,
                    headers={"Content-Type": "application/json"},
                    body=malicious_payload
                )
                if r["status_code"] in (200, 201, 204):
                    findings.append(self._make_finding(
                        "API3:2023",
                        f"Posible Mass Assignment en {method} {path}",
                        (
                            f"'{method} {path}' acepta la solicitud (HTTP {r['status_code']}) con campos como "
                            "'role', 'is_admin' y 'balance'. Puede permitir escalada de privilegios."
                        ),
                        "posiblemente_vulnerable", "alta",
                        {"method": method, "path": path, "status_code": r["status_code"]},
                        (
                            "Usar allowlist de campos aceptados en operaciones de escritura. "
                            "Ejemplos: strong_params (Rails), serializer fields (Django), "
                            "@JsonIgnore (Java), zod/yup schemas (Node.js)."
                        )
                    ))
        return findings

    # =========================================================================
    # API4:2023 — Unrestricted Resource Consumption
    # =========================================================================

    def check_api4_rate_limiting(self) -> List[Dict]:
        findings = []

        # Elegir un endpoint que responda
        test_path = next(
            (p["path"] for p in self.discovered_paths if p["status"] in (200, 401, 403)),
            "/api/users"
        )

        # 20 peticiones rápidas — medir si aparece 429
        status_codes = []
        start = time.time()
        for _ in range(20):
            r = self._http_request("GET", test_path)
            if r["status_code"]:
                status_codes.append(r["status_code"])
        elapsed = time.time() - start

        rate_limited = 429 in status_codes
        if not rate_limited and len(status_codes) >= 15:
            findings.append(self._make_finding(
                "API4:2023",
                f"Sin rate limiting en {test_path}",
                (
                    f"20 peticiones en {elapsed:.1f}s a '{test_path}' sin recibir HTTP 429. "
                    "No se detectó ninguna restricción de velocidad."
                ),
                "posiblemente_vulnerable", "media",
                {"endpoint": test_path, "peticiones": 20, "tiempo_s": round(elapsed, 2),
                 "respuestas": status_codes[:10], "codigo_429": False},
                (
                    "Implementar rate limiting por IP y por usuario autenticado. "
                    "Retornar HTTP 429 con headers: Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining. "
                    "Herramientas: nginx limit_req, django-ratelimit, express-rate-limit, Bucket4j (Java)."
                )
            ))

        # Verificar presencia de headers informativos de rate limiting
        r_check = self._http_request("GET", test_path)
        rl_headers = [h for h in r_check.get("headers", {})
                     if any(k in h.lower() for k in ["ratelimit", "rate-limit", "retry-after"])]
        if not rl_headers and not rate_limited:
            findings.append(self._make_finding(
                "API4:2023",
                "Headers de rate limiting ausentes en respuestas",
                (
                    f"Las respuestas de '{test_path}' no incluyen headers estándar de rate limiting "
                    "(X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset). "
                    "Los clientes no pueden conocer los límites de uso."
                ),
                "posiblemente_vulnerable", "baja",
                {"endpoint": test_path, "headers_rl": rl_headers},
                "Añadir headers X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset a todas las respuestas."
            ))
        return findings

    # =========================================================================
    # API5:2023 — Broken Function Level Authorization
    # =========================================================================

    def check_api5_function_auth(self) -> List[Dict]:
        findings = []

        # Métodos peligrosos en endpoints de solo lectura
        readable_paths = list({p["path"] for p in self.discovered_paths if p["status"] == 200}
                              | {"/api/users", "/api/products", "/api/items"})[:5]
        for path in readable_paths:
            for method in ["DELETE", "PUT", "PATCH"]:
                r = self._http_request(method, path,
                                       headers={"Content-Type": "application/json"}, body="{}")
                if r["status_code"] and r["status_code"] not in (401, 403, 404, 405):
                    findings.append(self._make_finding(
                        "API5:2023",
                        f"Método {method} aceptado sin autorización en {path}",
                        (
                            f"'{method} {path}' retorna HTTP {r['status_code']} sin requerir autorización. "
                            "Podría permitir modificación o eliminación de recursos."
                        ),
                        "posiblemente_vulnerable", "alta",
                        {"path": path, "method": method, "status_code": r["status_code"]},
                        (
                            "Aplicar RBAC (Role-Based Access Control) a nivel de método HTTP. "
                            "DELETE, PUT y PATCH deben requerir autenticación y permisos explícitos. "
                            "Retornar 405 Method Not Allowed para métodos no soportados."
                        )
                    ))

        # Acceso a endpoints administrativos sin autenticación
        for path in ["/api/admin", "/api/admin/users", "/api/administration",
                     "/api/management", "/api/internal", "/api/internal/users"]:
            r = self._http_request("GET", path)
            if r["status_code"] == 200:
                findings.append(self._make_finding(
                    "API5:2023",
                    f"Endpoint administrativo accesible sin autenticación: {path}",
                    (
                        f"'{path}' responde HTTP 200 sin autenticación. "
                        "Puede exponer gestión de usuarios, configuración o datos sensibles."
                    ),
                    "vulnerable", "critica",
                    {"path": path, "status_code": 200},
                    (
                        "Proteger endpoints administrativos con autenticación y RBAC. "
                        "Separar la API de administración de la API pública (dominio o puerto diferente). "
                        "Aplicar IP whitelisting para funciones de administración."
                    )
                ))
        return findings

    # =========================================================================
    # API6:2023 — Unrestricted Access to Sensitive Business Flows
    # =========================================================================

    def check_api6_sensitive_flows(self) -> List[Dict]:
        findings = []
        sensitive_flows = [
            ("/api/checkout",  "Proceso de compra"),
            ("/api/transfer",  "Transferencia de fondos"),
            ("/api/payment",   "Procesamiento de pago"),
            ("/api/register",  "Registro masivo de cuentas"),
            ("/api/vote",      "Sistema de votación"),
            ("/api/coupon",    "Generación de cupones"),
            ("/api/invite",    "Sistema de invitaciones"),
            ("/api/redeem",    "Redención de beneficios"),
        ]
        for path, flow_name in sensitive_flows:
            r = self._http_request("GET", path)
            if r["status_code"] and r["status_code"] not in (404,):
                findings.append(self._make_finding(
                    "API6:2023",
                    f"Flujo de negocio sensible accesible: {path} ({flow_name})",
                    (
                        f"El endpoint '{path}' ({flow_name}) es accesible (HTTP {r['status_code']}). "
                        "Sin controles adicionales puede ser abusado mediante automatización."
                    ),
                    "posiblemente_vulnerable", "media",
                    {"path": path, "flujo": flow_name, "status_code": r["status_code"]},
                    (
                        f"Para '{flow_name}': implementar CAPTCHA o challenge, "
                        "límites de uso por usuario/dispositivo/IP, "
                        "detección de comportamiento anómalo y validaciones de negocio server-side."
                    )
                ))
        return findings

    # =========================================================================
    # API7:2023 — Server Side Request Forgery (SSRF)
    # =========================================================================

    def check_api7_ssrf(self) -> List[Dict]:
        findings = []
        ssrf_payloads = [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://169.254.169.254/",  # AWS metadata
        ]
        ssrf_params = ["url", "callback", "redirect", "next", "target",
                       "dest", "webhook", "endpoint", "proxy", "src"]
        internal_indicators = ["root", "localhost", "internal", "169.254", "ami-id", "instance-id"]

        for path in [p["path"] for p in self.discovered_paths if p["status"] in (200, 400)][:6]:
            for param in ssrf_params[:4]:
                for payload in ssrf_payloads[:2]:
                    test_path = f"{path}?{param}={urllib.parse.quote(payload)}"
                    r = self._http_request("GET", test_path)
                    if r["status_code"] == 200 and any(ind in r["body"].lower() for ind in internal_indicators):
                        findings.append(self._make_finding(
                            "API7:2023",
                            f"Posible SSRF en {path} (parámetro '{param}')",
                            (
                                f"El parámetro '{param}' en '{path}' puede ser vulnerable a SSRF. "
                                "La respuesta contiene indicadores de acceso a recursos internos."
                            ),
                            "posiblemente_vulnerable", "alta",
                            {"path": test_path, "param": param, "payload": payload},
                            (
                                "Validar todas las URLs proporcionadas por el usuario contra una allowlist. "
                                "Bloquear peticiones a rangos privados: 127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16. "
                                "Usar un proxy egress con control de destinos permitidos."
                            )
                        ))

        # Endpoints de webhook que aceptan URLs sin validación
        for path in ["/api/webhook", "/api/callback", "/api/notify", "/api/proxy"]:
            r = self._http_request(
                "POST", path,
                headers={"Content-Type": "application/json"},
                body='{"url":"http://169.254.169.254/latest/meta-data/"}'
            )
            if r["status_code"] in (200, 201, 202):
                findings.append(self._make_finding(
                    "API7:2023",
                    f"Endpoint webhook sin validación de URL: {path}",
                    (
                        f"'{path}' acepta URLs de callback sin validación (HTTP {r['status_code']}). "
                        "Puede ser explotado para SSRF hacia la red interna."
                    ),
                    "posiblemente_vulnerable", "alta",
                    {"path": path, "status_code": r["status_code"]},
                    "Implementar allowlist de dominios en webhooks. Usar DNS rebinding protection."
                ))
        return findings

    # =========================================================================
    # API8:2023 — Security Misconfiguration
    # =========================================================================

    def check_api8_misconfiguration(self) -> List[Dict]:
        findings = []

        # Headers de seguridad requeridos
        r_root = self._http_request("GET", "/")
        if r_root["status_code"]:
            resp_headers_lc = {k.lower(): v for k, v in r_root["headers"].items()}
            required = {
                "Strict-Transport-Security": "HSTS no configurado — HTTP no redirige a HTTPS",
                "X-Content-Type-Options":    "MIME-sniffing no bloqueado",
                "X-Frame-Options":           "Vulnerable a Clickjacking",
                "Content-Security-Policy":   "Sin CSP — mayor superficie de XSS",
                "Permissions-Policy":        "Permisos de browser sin restringir",
            }
            missing = [(n, d) for n, d in required.items() if n.lower() not in resp_headers_lc]
            if missing:
                findings.append(self._make_finding(
                    "API8:2023",
                    "Headers de seguridad HTTP faltantes",
                    f"{len(missing)} headers de seguridad ausentes: " + "; ".join(n for n, _ in missing),
                    "posiblemente_vulnerable", "media",
                    {"headers_faltantes": [n for n, _ in missing],
                     "detalles": {n: d for n, d in missing}},
                    (
                        "Agregar todos los headers de seguridad recomendados:\n"
                        "  Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                        "  X-Content-Type-Options: nosniff\n"
                        "  X-Frame-Options: DENY\n"
                        "  Content-Security-Policy: default-src 'self'\n"
                        "  Permissions-Policy: geolocation=(), camera=(), microphone=()"
                    )
                ))

        # CORS permisivo
        r_cors = self._http_request(
            "OPTIONS", "/api",
            headers={"Origin": "https://evil.example.com",
                     "Access-Control-Request-Method": "GET"}
        )
        acao = r_cors["headers"].get("Access-Control-Allow-Origin", "")
        if acao in ("*", "https://evil.example.com"):
            findings.append(self._make_finding(
                "API8:2023",
                f"CORS permisivo — Access-Control-Allow-Origin: {acao}",
                (
                    f"La API refleja el origen del atacante (ACAO: '{acao}'). "
                    "Permite que sitios maliciosos hagan peticiones autenticadas a la API."
                ),
                "vulnerable" if acao == "https://evil.example.com" else "posiblemente_vulnerable",
                "alta" if acao == "https://evil.example.com" else "media",
                {"Access-Control-Allow-Origin": acao},
                (
                    "Usar allowlist explícita de orígenes permitidos. "
                    "Nunca usar Access-Control-Allow-Origin: * con credenciales. "
                    "Validar el header Origin en el servidor antes de reflejarlo."
                )
            ))

        # Mensajes de error verbosos
        r_err = self._http_request("GET", "/api/nonexistent-path-trigger-error-xyz-scan-agent")
        if r_err["status_code"] and r_err["body"]:
            error_indicators = ["stack trace", "traceback", "exception", "at line",
                               "sqlstate", "syntax error", "errno", "stacktrace"]
            found = [i for i in error_indicators if i in r_err["body"].lower()]
            if found:
                findings.append(self._make_finding(
                    "API8:2023",
                    "Mensajes de error verbosos — exposición de información técnica",
                    (
                        f"Las respuestas de error exponen información técnica interna: {found}. "
                        "Ayuda a los atacantes a mapear la arquitectura del sistema."
                    ),
                    "posiblemente_vulnerable", "media",
                    {"indicadores": found, "fragmento": r_err["body"][:300]},
                    (
                        "Usar mensajes de error genéricos en producción. "
                        "Loguear detalles técnicos solo en el servidor (nunca al cliente). "
                        "Implementar un manejador global de excepciones con respuestas estandarizadas."
                    )
                ))

        # Documentación de API expuesta públicamente
        doc_paths = ["/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json",
                     "/openapi.json", "/api-docs", "/docs", "/redoc", "/graphiql"]
        exposed_docs = [p for p in doc_paths if self._http_request("GET", p)["status_code"] == 200]
        if exposed_docs:
            findings.append(self._make_finding(
                "API8:2023",
                "Documentación de API expuesta públicamente",
                (
                    f"La documentación es accesible sin autenticación en: {exposed_docs}. "
                    "Expone la superficie de ataque completa a posibles atacantes."
                ),
                "posiblemente_vulnerable", "baja",
                {"rutas_documentacion": exposed_docs},
                (
                    "Proteger la documentación con autenticación en producción. "
                    "Deshabilitar Swagger UI en producción — solo en entornos de desarrollo."
                )
            ))
        return findings

    # =========================================================================
    # API9:2023 — Improper Inventory Management
    # =========================================================================

    def check_api9_inventory(self) -> List[Dict]:
        findings = []

        # Múltiples versiones de API activas
        version_candidates = [
            "/v1", "/v2", "/v3",
            "/api/v1", "/api/v2", "/api/v3",
            "/api/v1.0", "/api/v2.0",
            "/rest/v1", "/rest/v2",
        ]
        active = [
            {"path": p, "status": self._http_request("GET", p)["status_code"]}
            for p in version_candidates
            if self._http_request("GET", p)["status_code"] not in (None, 404)
        ]
        if len(active) > 1:
            findings.append(self._make_finding(
                "API9:2023",
                "Múltiples versiones de API activas simultáneamente",
                (
                    f"{len(active)} versiones activas detectadas: {[v['path'] for v in active]}. "
                    "Versiones antiguas pueden tener vulnerabilidades sin parchear."
                ),
                "posiblemente_vulnerable", "media",
                {"versiones_activas": active},
                (
                    "Mantener inventario actualizado de todas las versiones de API. "
                    "Dar de baja versiones obsoletas con tiempo suficiente de notificación a clientes. "
                    "Aplicar los mismos controles de seguridad a todas las versiones activas."
                )
            ))

        # Endpoints de debug/test en producción
        debug_paths = [
            "/api/debug", "/api/test", "/api/dev", "/api/internal",
            "/api/ping", "/api/echo", "/api/env", "/api/info",
            "/actuator", "/actuator/env", "/actuator/mappings", "/actuator/beans",
            "/__debug__", "/_internal", "/phpinfo.php", "/info.php"
        ]
        exposed_debug = [p for p in debug_paths if self._http_request("GET", p)["status_code"] == 200]
        if exposed_debug:
            findings.append(self._make_finding(
                "API9:2023",
                "Endpoints de debug/test accesibles en producción",
                (
                    f"Endpoints de desarrollo accesibles: {exposed_debug}. "
                    "Pueden exponer configuración, variables de entorno o funciones inseguras."
                ),
                "vulnerable", "alta",
                {"endpoints_debug": exposed_debug},
                (
                    "Deshabilitar todos los endpoints de debug/test en producción. "
                    "Usar variables de entorno para activar funcionalidad de debug solo en desarrollo. "
                    "Verificar en el pipeline de CI/CD que no existan endpoints de debug en builds productivos."
                )
            ))
        return findings

    # =========================================================================
    # API10:2023 — Unsafe Consumption of APIs
    # =========================================================================

    def check_api10_unsafe_consumption(self) -> List[Dict]:
        findings = []

        # Open Redirect — la API redirige a URLs arbitrarias sin validación
        redirect_params = ["redirect", "next", "return", "returnUrl", "callback", "continue", "url"]
        malicious_url = "https://evil.example.com/phishing"
        for param in redirect_params:
            r = self._http_request("GET", f"/?{param}={urllib.parse.quote(malicious_url)}")
            if r["status_code"] in (301, 302, 303, 307, 308):
                location = r["headers"].get("Location", "")
                if "evil.example.com" in location:
                    findings.append(self._make_finding(
                        "API10:2023",
                        f"Open Redirect — parámetro '{param}'",
                        (
                            f"El parámetro '{param}' redirige a URLs arbitrarias sin validación. "
                            f"Destino detectado: '{location}'. Puede usarse para phishing."
                        ),
                        "vulnerable", "media",
                        {"param": param, "redirect_to": location},
                        (
                            "Validar todas las URLs de redirección contra allowlist de dominios. "
                            "Usar redirecciones relativas cuando sea posible. "
                            "Mostrar advertencia antes de redirigir fuera del dominio propio."
                        )
                    ))

        # Nota informativa sobre revisión manual requerida
        findings.append(self._make_finding(
            "API10:2023",
            "Revisión manual requerida — consumo de APIs de terceros",
            (
                "API10:2023 requiere análisis del código fuente: verificar que los datos "
                "de APIs externas sean validados (esquema, tipos, tamaño) antes de procesarse. "
                "Este check no puede automatizarse completamente."
            ),
            "no_aplicable", "baja",
            {"nota": "Requiere inspección manual del código fuente"},
            (
                "En el código: 1) Validar esquema de respuestas de APIs externas. "
                "2) Implementar timeouts en todas las llamadas externas. "
                "3) Manejar errores de APIs externas sin exponer detalles al cliente final. "
                "4) No ejecutar datos externos sin sanitización previa."
            )
        ))
        return findings

    # =========================================================================
    # Helpers
    # =========================================================================

    def _make_finding(
        self,
        check_id: str,
        titulo: str,
        descripcion: str,
        estado: str,
        severidad: str,
        evidencia: Dict,
        recomendacion: str
    ) -> Dict[str, Any]:
        """Crea un hallazgo estructurado en formato estándar del proyecto."""
        api_info = self.OWASP_API_TOP_10.get(check_id, {})
        cvss = api_info.get("cvss_base", 5.0)
        if estado == "posiblemente_vulnerable":
            cvss = round(cvss * 0.7, 1)
        elif estado == "no_aplicable":
            cvss = 0.0
        return {
            "id": f"{check_id}-{len(self.findings) + 1:03d}",
            "fuente": "api_security_checker",
            "check_id": check_id,
            "titulo": titulo,
            "descripcion": descripcion,
            "estado": estado,
            "severidad": severidad,
            "cvss_score": cvss,
            "owasp_api_category": f"{check_id} — {api_info.get('nombre', '')}",
            "owasp_web_eq": api_info.get("owasp_web_eq", ""),
            "evidencia": evidencia,
            "recomendacion": recomendacion,
            "timestamp": datetime.now().isoformat()
        }

    def save_results(self, output_dir: str, target: str) -> str:
        """Guarda los resultados en JSON para que el parser los procese."""
        safe_target = target.replace(":", "_").replace("/", "_").replace(".", "_")
        output_path = Path(output_dir) / f"api_security_{safe_target}.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output = {
            "target": self.base_url,
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "vulnerable_count": sum(1 for f in self.findings if f["estado"] == "vulnerable"),
            "posible_count": sum(1 for f in self.findings if f["estado"] == "posiblemente_vulnerable"),
            "discovered_paths": self.discovered_paths,
            "findings": self.findings
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print(f"[OK] Resultados API Security guardados en: {output_path}")
        return str(output_path)


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="OWASP API Security Top 10 (2023) — Checker")
    parser.add_argument("--target", required=True, help="Hostname o IP del objetivo")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--https", action="store_true", dest="use_https")
    parser.add_argument("--output-dir", default="./outputs")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    checker = APISecurityChecker(
        target=args.target,
        port=args.port,
        use_https=args.use_https,
        verbose=args.verbose
    )
    checker.run_all_checks()
    checker.save_results(args.output_dir, args.target)
