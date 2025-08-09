#!/usr/bin/env python3
"""
Tarea de análisis estático con Semgrep
Ejecutada por el agente estático
"""

from crewai import Task
from typing import Dict, Any

class StaticAnalysisTask:
    """Tarea para validar vulnerabilidades mediante análisis estático"""
    
    @staticmethod
    def create_task(agent, extracted_vulnerabilities: str, source_code_path: str) -> Task:
        """Crea la tarea de análisis estático"""
        
        description = f"""
        Valida las vulnerabilidades extraídas del reporte mediante análisis estático del código fuente.
        
        VULNERABILIDADES EXTRAÍDAS:
        {extracted_vulnerabilities}
        
        CÓDIGO FUENTE A ANALIZAR: {source_code_path}
        
        Tu objetivo es:
        1. Analizar las vulnerabilidades extraídas del reporte
        2. Para cada vulnerabilidad, determinar:
           - Qué reglas de Semgrep usar para detectarla
           - Qué archivos/directorios específicos analizar
           - Qué patrones de código buscar
        
        3. Ejecutar análisis estático usando la herramienta Semgrep con:
           - Reglas específicas para cada tipo de vulnerabilidad
           - Configuraciones apropiadas por lenguaje
           - Filtros de severidad relevantes
        
        4. Correlacionar los hallazgos de Semgrep con las vulnerabilidades del reporte:
           - Identificar coincidencias por tipo de vulnerabilidad
           - Verificar ubicaciones (archivos, líneas)
           - Confirmar patrones de código vulnerable
        
        5. Para cada vulnerabilidad del reporte, determinar:
           - CONFIRMADA: Si Semgrep encontró evidencia en el código
           - NO_CONFIRMADA: Si no se encontró evidencia
           - PARCIAL: Si se encontró código similar pero no exacto
           - NO_APLICABLE: Si el tipo de vulnerabilidad no es detectable por análisis estático
        
        Usa tu experiencia en análisis estático para:
        - Seleccionar las reglas de Semgrep más apropiadas
        - Interpretar los resultados en el contexto de las vulnerabilidades reportadas
        - Identificar falsos positivos y negativos
        - Proporcionar evidencia técnica específica
        
        IMPORTANTE: Retorna ÚNICAMENTE un JSON válido con la estructura especificada.
        """
        
        expected_output = """
        Un JSON válido con la siguiente estructura:
        {
            "analysis_metadata": {
                "analysis_date": "string",
                "source_path": "string",
                "total_vulnerabilities_analyzed": "number",
                "semgrep_version": "string",
                "rules_used": ["string"]
            },
            "validation_results": [
                {
                    "vulnerability_id": "string (del reporte original)",
                    "vulnerability_title": "string",
                    "validation_status": "CONFIRMADA|NO_CONFIRMADA|PARCIAL|NO_APLICABLE",
                    "confidence_level": "High|Medium|Low",
                    "semgrep_findings": [
                        {
                            "rule_id": "string",
                            "file_path": "string",
                            "line_number": "number",
                            "code_snippet": "string",
                            "severity": "string",
                            "message": "string"
                        }
                    ],
                    "analysis_details": {
                        "rules_applied": ["string"],
                        "files_scanned": "number",
                        "match_reasoning": "string",
                        "false_positive_likelihood": "High|Medium|Low"
                    },
                    "evidence": "string",
                    "recommendations": "string"
                }
            ],
            "summary": {
                "confirmed_vulnerabilities": "number",
                "unconfirmed_vulnerabilities": "number",
                "partial_matches": "number",
                "not_applicable": "number",
                "overall_confidence": "High|Medium|Low",
                "additional_findings": "string"
            }
        }
        """
        
        return Task(
            description=description,
            expected_output=expected_output,
            agent=agent
        )
    
    @staticmethod
    def get_cwe_to_semgrep_mapping() -> Dict[str, list]:
        """Mapeo de CWEs a reglas de Semgrep"""
        return {
            "CWE-89": [  # SQL Injection
                "p/sql-injection",
                "p/security-audit",
                "rules.security.sql-injection"
            ],
            "CWE-79": [  # XSS
                "p/xss",
                "p/security-audit",
                "rules.security.xss"
            ],
            "CWE-22": [  # Path Traversal
                "p/path-traversal",
                "p/security-audit",
                "rules.security.path-traversal"
            ],
            "CWE-78": [  # Command Injection
                "p/command-injection",
                "p/security-audit",
                "rules.security.command-injection"
            ],
            "CWE-94": [  # Code Injection
                "p/code-injection",
                "p/security-audit",
                "rules.security.code-injection"
            ],
            "CWE-352": [  # CSRF
                "p/csrf",
                "p/security-audit",
                "rules.security.csrf"
            ],
            "CWE-434": [  # File Upload
                "p/file-upload",
                "p/security-audit",
                "rules.security.file-upload"
            ],
            "CWE-798": [  # Hard-coded Credentials
                "p/secrets",
                "p/security-audit",
                "rules.security.hardcoded-secrets"
            ],
            "CWE-287": [  # Authentication Bypass
                "p/authentication",
                "p/security-audit",
                "rules.security.authentication"
            ],
            "CWE-862": [  # Authorization
                "p/authorization",
                "p/security-audit",
                "rules.security.authorization"
            ]
        }
    
    @staticmethod
    def get_language_specific_configs() -> Dict[str, Dict[str, Any]]:
        """Configuraciones específicas por lenguaje"""
        return {
            "python": {
                "rules": ["p/python", "p/flask", "p/django"],
                "extensions": [".py"],
                "exclude_patterns": ["**/venv/**", "**/__pycache__/**"]
            },
            "javascript": {
                "rules": ["p/javascript", "p/nodejs", "p/react"],
                "extensions": [".js", ".jsx", ".ts", ".tsx"],
                "exclude_patterns": ["**/node_modules/**", "**/dist/**"]
            },
            "java": {
                "rules": ["p/java", "p/spring"],
                "extensions": [".java"],
                "exclude_patterns": ["**/target/**", "**/build/**"]
            },
            "php": {
                "rules": ["p/php", "p/laravel"],
                "extensions": [".php"],
                "exclude_patterns": ["**/vendor/**"]
            },
            "csharp": {
                "rules": ["p/csharp", "p/dotnet"],
                "extensions": [".cs"],
                "exclude_patterns": ["**/bin/**", "**/obj/**"]
            }
        }