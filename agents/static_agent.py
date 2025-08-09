#!/usr/bin/env python3
"""
Agente Estático - Valida vulnerabilidades usando análisis estático con Semgrep
Utiliza LLM para correlacionar hallazgos con vulnerabilidades reportadas
"""

from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, Any, List
import json

class StaticAgent:
    """Agente especializado en análisis estático de código con Semgrep"""
    
    def __init__(self, semgrep_tool):
        self.semgrep_tool = semgrep_tool
        self.llm = ChatOpenAI(
            model="gpt-5-mini",
            temperature=0.1
        )
        
        self.agent = Agent(
            role="Especialista en Análisis Estático de Código",
            goal="Validar vulnerabilidades mediante análisis estático usando Semgrep y correlacionar con reportes de seguridad",
            backstory="""
            Eres un experto en análisis estático de código con más de 8 años de experiencia 
            en herramientas como Semgrep, SonarQube, y Checkmarx. Tu especialidad es 
            identificar vulnerabilidades en código fuente y correlacionar hallazgos 
            con reportes de seguridad.
            
            Tu experiencia incluye:
            - Configuración y optimización de reglas de Semgrep
            - Análisis de falsos positivos y negativos
            - Correlación de hallazgos estáticos con vulnerabilidades reales
            - Conocimiento profundo de patrones de código inseguro
            - Experiencia en múltiples lenguajes de programación
            
            Tu trabajo es crucial para validar si las vulnerabilidades reportadas
            realmente existen en el código fuente y proporcionar evidencia técnica
            precisa de su ubicación y naturaleza.
            """,
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=[self.semgrep_tool]
        )
    
    def get_semgrep_rules_mapping(self) -> Dict[str, List[str]]:
        """Mapeo de CWEs a reglas específicas de Semgrep"""
        return {
            "CWE-89": [  # SQL Injection
                "python.django.security.injection.sql.django-sql-injection",
                "python.flask.security.injection.sql.sql-injection-flask-sqlalchemy",
                "javascript.express.security.injection.sql.express-sql-injection",
                "java.spring.security.injection.sql.spring-sql-injection",
                "php.lang.security.injection.sql.sql-injection",
                "generic.secrets.security.detected-sql-injection"
            ],
            "CWE-79": [  # XSS
                "python.django.security.injection.xss.django-xss",
                "python.flask.security.injection.xss.flask-xss",
                "javascript.express.security.injection.xss.express-xss",
                "java.spring.security.injection.xss.spring-xss",
                "php.lang.security.injection.xss.xss",
                "typescript.react.security.injection.xss.react-xss"
            ],
            "CWE-352": [  # CSRF
                "python.django.security.csrf.django-csrf-disabled",
                "python.flask.security.csrf.flask-csrf-disabled",
                "javascript.express.security.csrf.express-csrf-disabled",
                "java.spring.security.csrf.spring-csrf-disabled"
            ],
            "CWE-22": [  # Path Traversal
                "python.lang.security.traversal.path-traversal",
                "javascript.lang.security.traversal.path-traversal",
                "java.lang.security.traversal.path-traversal",
                "php.lang.security.traversal.path-traversal",
                "generic.secrets.security.detected-path-traversal"
            ],
            "CWE-78": [  # Command Injection
                "python.lang.security.injection.command.command-injection",
                "javascript.lang.security.injection.command.command-injection",
                "java.lang.security.injection.command.command-injection",
                "php.lang.security.injection.command.command-injection",
                "bash.lang.security.injection.command.command-injection"
            ],
            "CWE-94": [  # Code Injection
                "python.lang.security.injection.code.code-injection",
                "javascript.lang.security.injection.code.code-injection",
                "java.lang.security.injection.code.code-injection",
                "php.lang.security.injection.code.code-injection"
            ],
            "CWE-98": [  # File Inclusion
                "php.lang.security.inclusion.file-inclusion",
                "python.lang.security.inclusion.file-inclusion",
                "javascript.lang.security.inclusion.file-inclusion"
            ],
            "CWE-200": [  # Information Disclosure
                "generic.secrets.security.detected-private-key",
                "generic.secrets.security.detected-password",
                "python.lang.security.disclosure.information-disclosure",
                "javascript.lang.security.disclosure.information-disclosure",
                "java.lang.security.disclosure.information-disclosure"
            ],
            "CWE-287": [  # Authentication Bypass
                "python.django.security.auth.django-auth-bypass",
                "python.flask.security.auth.flask-auth-bypass",
                "javascript.express.security.auth.express-auth-bypass",
                "java.spring.security.auth.spring-auth-bypass"
            ],
            "CWE-327": [  # Weak Cryptography
                "python.lang.security.crypto.weak-crypto",
                "javascript.lang.security.crypto.weak-crypto",
                "java.lang.security.crypto.weak-crypto",
                "php.lang.security.crypto.weak-crypto",
                "generic.secrets.security.detected-weak-crypto"
            ],
            "CWE-319": [  # Insecure Transport
                "python.lang.security.transport.insecure-transport",
                "javascript.lang.security.transport.insecure-transport",
                "java.lang.security.transport.insecure-transport",
                "generic.secrets.security.detected-insecure-transport"
            ],
            "CWE-601": [  # Open Redirect
                "python.django.security.redirect.django-open-redirect",
                "python.flask.security.redirect.flask-open-redirect",
                "javascript.express.security.redirect.express-open-redirect",
                "java.spring.security.redirect.spring-open-redirect"
            ],
            "CWE-798": [  # Hardcoded Credentials
                "generic.secrets.security.detected-hardcoded-password",
                "generic.secrets.security.detected-hardcoded-key",
                "python.lang.security.hardcoded.hardcoded-credentials",
                "javascript.lang.security.hardcoded.hardcoded-credentials",
                "java.lang.security.hardcoded.hardcoded-credentials"
            ],
            "CWE-20": [  # Input Validation
                "python.lang.security.validation.input-validation",
                "javascript.lang.security.validation.input-validation",
                "java.lang.security.validation.input-validation",
                "php.lang.security.validation.input-validation"
            ]
        }
    
    def get_language_detection_patterns(self) -> Dict[str, List[str]]:
        """Patrones para detectar lenguajes de programación en el directorio"""
        return {
            "python": [".py", "requirements.txt", "setup.py", "pyproject.toml"],
            "javascript": [".js", ".jsx", "package.json", ".ts", ".tsx"],
            "java": [".java", "pom.xml", "build.gradle", ".class"],
            "php": [".php", "composer.json", ".phtml"],
            "csharp": [".cs", ".csproj", ".sln"],
            "go": [".go", "go.mod", "go.sum"],
            "ruby": [".rb", "Gemfile", ".gemspec"],
            "rust": [".rs", "Cargo.toml"],
            "cpp": [".cpp", ".c", ".h", ".hpp", "CMakeLists.txt"],
            "kotlin": [".kt", ".kts"]
        }
    
    def get_validation_schema(self) -> Dict[str, Any]:
        """Esquema para el reporte de validación estática"""
        return {
            "static_analysis_results": {
                "scan_summary": {
                    "target_directory": "string",
                    "scan_timestamp": "string",
                    "languages_detected": ["string"],
                    "total_files_scanned": "int",
                    "semgrep_rules_used": ["string"]
                },
                "vulnerability_validations": [
                    {
                        "vulnerability_id": "string - ID del reporte original",
                        "validation_status": "string - CONFIRMED|NOT_FOUND|PARTIAL|UNCERTAIN",
                        "confidence_level": "string - HIGH|MEDIUM|LOW",
                        "semgrep_findings": [
                            {
                                "rule_id": "string",
                                "file_path": "string",
                                "line_number": "int",
                                "code_snippet": "string",
                                "severity": "string",
                                "message": "string"
                            }
                        ],
                        "correlation_analysis": "string - Análisis de correlación con el reporte",
                        "evidence_summary": "string - Resumen de evidencia encontrada",
                        "false_positive_assessment": "string - Evaluación de falsos positivos",
                        "additional_context": "string - Contexto adicional del código"
                    }
                ],
                "additional_findings": [
                    {
                        "description": "string - Hallazgos adicionales relevantes",
                        "severity": "string",
                        "location": "string",
                        "relevance_to_report": "string"
                    }
                ],
                "analysis_limitations": ["string - Limitaciones del análisis"],
                "recommendations": ["string - Recomendaciones basadas en hallazgos"]
            }
        }
    
    def get_semgrep_command_templates(self) -> Dict[str, str]:
        """Templates de comandos Semgrep para diferentes escenarios"""
        return {
            "comprehensive": "semgrep --config=auto --json --verbose",
            "security_focused": "semgrep --config=p/security-audit --json --verbose",
            "owasp_top10": "semgrep --config=p/owasp-top-ten --json --verbose",
            "cwe_specific": "semgrep --config=p/cwe-top-25 --json --verbose",
            "language_specific": "semgrep --config=p/{language} --json --verbose",
            "custom_rules": "semgrep --config={custom_rules_path} --json --verbose"
        }
    
    def get_correlation_strategies(self) -> Dict[str, str]:
        """Estrategias para correlacionar hallazgos de Semgrep con vulnerabilidades reportadas"""
        return {
            "exact_match": "Coincidencia exacta de CWE y ubicación",
            "pattern_match": "Coincidencia de patrones de vulnerabilidad",
            "semantic_match": "Coincidencia semántica basada en descripción",
            "location_proximity": "Proximidad de ubicación en archivos similares",
            "code_context": "Análisis del contexto del código circundante"
        }