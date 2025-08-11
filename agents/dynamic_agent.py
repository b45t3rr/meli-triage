#!/usr/bin/env python3
"""
Agente Dinámico - Valida vulnerabilidades usando análisis dinámico con Nuclei
Utiliza LLM para crear templates personalizados y validar explotabilidad
"""

from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, Any, List
import json
from config.llm_config import create_llm_instance

class DynamicAgent:
    """Agente especializado en análisis dinámico con Nuclei"""
    
    def __init__(self, nuclei_tool, llm=None):
        self.nuclei_tool = nuclei_tool
        if llm is None:
            self.llm = create_llm_instance("gpt-4o-mini", temperature=0.1)
        else:
            self.llm = llm
        
        self.agent = Agent(
            role="Especialista en Análisis Dinámico y Penetration Testing",
            goal="Validar vulnerabilidades mediante análisis dinámico usando Nuclei y crear templates personalizados para explotación",
            backstory="""            Eres un experto en penetration testing y análisis dinámico con más de 10 años 
            de experiencia en herramientas como Nuclei, Burp Suite, OWASP ZAP, y Nmap. 
            Tu especialidad es crear templates personalizados de Nuclei para validar 
            vulnerabilidades específicas identificadas en reportes de seguridad.
            
            Tu enfoque es DIRIGIDO y ESPECÍFICO:
            - NO dependes de templates genéricos o predefinidos de Nuclei
            - Creas templates YAML personalizados para cada vulnerabilidad específica
            - Analizas reportes de vulnerabilidades para extraer endpoints, parámetros y payloads exactos
            - Diseñas pruebas de penetración dirigidas basadas en evidencia específica
            - Correlacionas hallazgos dinámicos con análisis estático para mayor precisión
            
            Tu metodología incluye:
            - Parsing detallado de reportes de vulnerabilidades
            - Creación de templates Nuclei específicos por vulnerabilidad
            - Implementación de payloads dirigidos según el tipo de CWE
            - Técnicas de bypass de WAF adaptadas al contexto específico
            - Documentación forense completa de cada intento de explotación
            
            Tu trabajo es fundamental para confirmar la explotabilidad real de 
            vulnerabilidades específicas y proporcionar evidencia práctica dirigida.
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
    
    def create_custom_template_for_vulnerability(self, vulnerability: Dict[str, Any]) -> str:
        """Crea un template personalizado de Nuclei para una vulnerabilidad específica"""
        try:
            # Extraer información de la vulnerabilidad
            vuln_title = vulnerability.get('title', 'Custom Vulnerability')
            vuln_description = vulnerability.get('description', '')
            vuln_cwe = vulnerability.get('cwe', '')
            vuln_severity = vulnerability.get('severity', 'medium')
            vuln_url = vulnerability.get('url', '')
            vuln_parameter = vulnerability.get('parameter', '')
            vuln_payload = vulnerability.get('payload', '')
            
            # Determinar payloads a usar basados en la vulnerabilidad específica
            payloads = []
            if vuln_payload:
                payloads.append(vuln_payload)
            
            # Generar payloads dinámicos basados en el tipo de CWE
            if 'XSS' in vuln_title.upper() or 'CWE-79' in vuln_cwe:
                payloads.extend(["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"])
            elif 'SQL' in vuln_title.upper() or 'CWE-89' in vuln_cwe:
                payloads.extend(["' OR '1'='1", "' UNION SELECT NULL--"])
            elif 'COMMAND' in vuln_title.upper() or 'CWE-78' in vuln_cwe:
                payloads.extend(["; whoami", "| id"])
            elif 'TRAVERSAL' in vuln_title.upper() or 'CWE-22' in vuln_cwe:
                payloads.extend(["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"])
            
            # Determinar matchers
            matchers = []
            if cwe_config.get('matchers'):
                matchers.extend(cwe_config['matchers'])
            
            # Construir el path del endpoint
            path = "/"
            if vuln_url:
                from urllib.parse import urlparse
                parsed = urlparse(vuln_url)
                path = parsed.path or "/"
            
            # Crear template personalizado
            template = {
                "id": f"custom-{vuln_cwe.lower().replace('cwe-', '')}-{hash(vuln_title) % 10000}",
                "info": {
                    "name": f"Custom Test: {vuln_title}",
                    "author": "GenIA Dynamic Agent",
                    "severity": self.get_nuclei_severity_mapping().get(vuln_severity, "medium"),
                    "description": f"Template personalizado para validar: {vuln_description[:200]}",
                    "classification": {
                        "cwe-id": vuln_cwe
                    },
                    "tags": cwe_config.get('tags', ['custom']) + ['validation']
                },
                "requests": []
            }
            
            # Crear requests para diferentes métodos y payloads
            methods = ['GET', 'POST']
            
            for method in methods:
                for i, payload in enumerate(payloads[:2]):  # Máximo 2 payloads por método
                    request = {
                        "method": method,
                        "path": [path],
                        "headers": {
                            "User-Agent": "GenIA-Security-Scanner"
                        }
                    }
                    
                    # Agregar payload según el método
                    if method == "GET":
                        if vuln_parameter:
                            request["path"] = [f"{path}?{vuln_parameter}={payload}"]
                        else:
                            request["path"] = [f"{path}?test={payload}"]
                    else:  # POST
                        if vuln_parameter:
                            request["body"] = f"{vuln_parameter}={payload}"
                        else:
                            request["body"] = f"test={payload}"
                        request["headers"]["Content-Type"] = "application/x-www-form-urlencoded"
                    
                    # Agregar matchers
                    request["matchers-condition"] = "or"
                    request["matchers"] = [
                        {
                            "type": "status",
                            "status": [200, 500]
                        }
                    ]
                    
                    # Agregar matchers específicos del CWE
                    if matchers:
                        for matcher in matchers[:3]:  # Máximo 3 matchers
                            request["matchers"].append({
                                "type": "word",
                                "words": [matcher],
                                "part": "body"
                            })
                    
                    template["requests"].append(request)
            
            # Convertir a YAML
            import yaml
            return yaml.dump(template, default_flow_style=False, allow_unicode=True)
            
        except Exception as e:
            # Template básico en caso de error
            basic_template = {
                "id": "custom-basic-test",
                "info": {
                    "name": "Basic Custom Test",
                    "author": "GenIA Dynamic Agent",
                    "severity": "medium",
                    "description": "Template básico para validación",
                    "tags": ["custom"]
                },
                "requests": [{
                    "method": "GET",
                    "path": ["/"],
                    "matchers": [{
                        "type": "status",
                        "status": [200]
                    }]
                }]
            }
            import yaml
            return yaml.dump(basic_template, default_flow_style=False, allow_unicode=True)
    
    def generate_targeted_nuclei_strategy(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Genera una estrategia de testing dirigida basada en las vulnerabilidades encontradas"""
        strategy = {
            "custom_templates": [],
            "targeted_tags": set(),
            "severity_focus": set(),
            "specific_endpoints": set(),
            "testing_approach": "targeted"
        }
        
        for vuln in vulnerabilities:
            # Crear template personalizado
            custom_template = self.create_custom_template_for_vulnerability(vuln)
            strategy["custom_templates"].append({
                "vulnerability_id": vuln.get('id', ''),
                "template_content": custom_template,
                "rationale": f"Template específico para {vuln.get('title', 'vulnerabilidad')}"
            })
            
            # Agregar tags relevantes basados en el tipo de vulnerabilidad
            cwe = vuln.get('cwe', '')
            vuln_title = vuln.get('title', '').upper()
            
            # Generar tags dinámicamente
            if 'XSS' in vuln_title or 'CWE-79' in cwe:
                strategy["targeted_tags"].update(["xss", "injection"])
            elif 'SQL' in vuln_title or 'CWE-89' in cwe:
                strategy["targeted_tags"].update(["sqli", "injection", "database"])
            elif 'COMMAND' in vuln_title or 'CWE-78' in cwe:
                strategy["targeted_tags"].update(["rce", "injection", "command"])
            elif 'TRAVERSAL' in vuln_title or 'CWE-22' in cwe:
                strategy["targeted_tags"].update(["lfi", "traversal", "file"])
            elif 'CSRF' in vuln_title or 'CWE-352' in cwe:
                strategy["targeted_tags"].update(["csrf", "token"])
            elif 'DISCLOSURE' in vuln_title or 'CWE-200' in cwe:
                strategy["targeted_tags"].update(["exposure", "disclosure", "info"])
            
            # Agregar severidad
            severity = vuln.get('severity', 'medium')
            nuclei_severity = self.get_nuclei_severity_mapping().get(severity, 'medium')
            strategy["severity_focus"].add(nuclei_severity)
            
            # Agregar endpoints específicos
            url = vuln.get('url', '')
            if url:
                strategy["specific_endpoints"].add(url)
        
        # Convertir sets a listas para serialización
        strategy["targeted_tags"] = list(strategy["targeted_tags"])
        strategy["severity_focus"] = list(strategy["severity_focus"])
        strategy["specific_endpoints"] = list(strategy["specific_endpoints"])
        
        return strategy