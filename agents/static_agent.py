#!/usr/bin/env python3
"""
Agente Estático - Valida vulnerabilidades usando análisis estático con Semgrep
Utiliza LLM para correlacionar hallazgos con vulnerabilidades reportadas
"""

from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, Any, List
import json
import re
from config.llm_config import create_llm_instance

class StaticAgent:
    """Agente especializado en análisis estático de código usando Semgrep con análisis inteligente por LLM.
    
    Este agente implementa un enfoque avanzado que:
    1. Ejecuta un escaneo genérico completo del código fuente con Semgrep
    2. Usa un LLM para analizar y correlacionar inteligentemente los resultados
    3. Correlaciona hallazgos de Semgrep con vulnerabilidades reportadas
    4. Proporciona análisis contextual y razonamiento detallado
    
    Características principales:
    - Escaneo genérico con configuración automática de Semgrep
    - Análisis inteligente por LLM para correlación de vulnerabilidades
    - Razonamiento contextual y explicaciones detalladas
    - Fallback automático cuando el LLM no está disponible
    - Mayor precisión en la detección de vulnerabilidades
    """
    
    def __init__(self, semgrep_tool, llm=None):
        self.semgrep_tool = semgrep_tool
        if llm is None:
            self.llm = create_llm_instance("gpt-4o-mini", temperature=0.1)
        else:
            self.llm = llm
        
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
    
    def perform_generic_scan(self, target_path: str) -> Dict[str, Any]:
        """Ejecuta un escaneo genérico con Semgrep usando configuración automática"""
        try:
            # Ejecutar escaneo genérico con configuración automática
            scan_result = self.semgrep_tool.get_raw_results(
                target_path=target_path,
                config="auto",  # Configuración automática para detectar múltiples tipos de vulnerabilidades
                rules=None,
                language=None,
                severity=None,
                exclude_patterns=["*.git*", "*.log", "*.tmp", "node_modules/*", "venv/*", "__pycache__/*"]
            )
            
            # Verificar si hay errores en el resultado
            if "error" in scan_result:
                return {"success": False, "error": scan_result["error"]}
            
            return {"success": True, "results": scan_result}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def perform_targeted_scan(self, target_path: str, reported_vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Ejecuta un escaneo dirigido generando reglas dinámicamente basándose en las vulnerabilidades reportadas"""
        try:
            # Generar reglas dinámicas basadas en las vulnerabilidades reportadas
            dynamic_rules = self._generate_dynamic_rules(reported_vulnerabilities, target_path)
            
            # Ejecutar escaneo con reglas dinámicas
            scan_result = self.semgrep_tool.get_raw_results(
                target_path=target_path,
                config="auto",  # Mantener configuración automática como base
                rules=dynamic_rules if dynamic_rules else None,
                language=None,
                severity=None,
                exclude_patterns=["*.git*", "*.log", "*.tmp", "node_modules/*", "venv/*", "__pycache__/*"]
            )
            
            # Verificar si hay errores en el resultado
            if "error" in scan_result:
                return {"success": False, "error": scan_result["error"]}
            
            return {"success": True, "results": scan_result, "dynamic_rules_used": dynamic_rules}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def analyze_vulnerabilities_with_llm(self, semgrep_results: Dict[str, Any], reported_vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Usa el LLM para analizar y correlacionar los resultados de Semgrep con las vulnerabilidades reportadas"""
        try:
            # Preparar el prompt para el LLM
            semgrep_findings = semgrep_results.get('results', [])
            
            analysis_prompt = f"""
            Eres un experto en análisis de seguridad. Tu tarea es correlacionar los hallazgos de Semgrep con las vulnerabilidades reportadas.
            
            VULNERABILIDADES REPORTADAS:
            {json.dumps(reported_vulnerabilities, indent=2)}
            
            HALLAZGOS DE SEMGREP:
            {json.dumps(semgrep_findings, indent=2)}
            
            Para cada vulnerabilidad reportada, analiza si existe evidencia en los hallazgos de Semgrep que la confirme.
            Considera:
            1. Tipos de vulnerabilidad similares (ej: path traversal, directory traversal)
            2. Ubicaciones de archivos mencionadas
            3. Patrones de código que coincidan
            4. Funciones o métodos específicos
            5. Parámetros o variables mencionadas
            
            IMPORTANTE: Para vulnerabilidades con status PROBABLE o CONFIRMADA, SIEMPRE incluye evidencia detallada en matching_findings.
            
            Retorna un JSON con la siguiente estructura:
            {{
                "static_analysis_results": {{
                    "vulnerability_id": "string",
                    "vulnerability_title": "string",
                    "vulnerability_type": "string",
                    "validation_status": "CONFIRMED|NOT_FOUND|PARTIAL|INCONCLUSIVE",
                    "confidence_level": "High|Medium|Low",
                    "evidence": {{
                        "code_snippets": [
                            {{
                                "file_path": "string",
                                "line_numbers": "string",
                                "vulnerable_code": "string",
                                "vulnerability_pattern": "string"
                            }}
                        ],
                        "analysis_summary": "string - Resumen del análisis realizado"
                    }}
                }}
            }}
            """
            
            # Usar el LLM para analizar
            if hasattr(self, 'llm') and self.llm:
                response = self.llm.invoke(analysis_prompt)
                try:
                    # Extraer el contenido de la respuesta
                    if hasattr(response, 'content'):
                        response_text = response.content
                    else:
                        response_text = str(response)
                    
                    # Limpiar la respuesta para extraer JSON
                    response_text = response_text.strip()
                    
                    # Buscar JSON en la respuesta usando diferentes patrones
                    json_start = response_text.find('{')
                    json_end = response_text.rfind('}') + 1
                    
                    if json_start != -1 and json_end > json_start:
                        json_text = response_text[json_start:json_end]
                        result = json.loads(json_text)
                    else:
                        # Intentar parsear toda la respuesta
                        result = json.loads(response_text)
                    
                    # Convertir formato de correlaciones al formato simplificado
                    if 'correlations' in result and result['correlations']:
                        # Tomar la primera correlación como resultado principal
                        first_correlation = result['correlations'][0]
                        
                        # Convertir matching_findings a code_snippets
                        code_snippets = []
                        for finding in first_correlation.get('matching_findings', []):
                            code_snippets.append({
                                "file_path": finding.get('file_path', ''),
                                "line_numbers": str(finding.get('line_number', '')),
                                "vulnerable_code": finding.get('code_snippet', ''),
                                "vulnerability_pattern": finding.get('message', '')
                            })
                        
                        simplified_result = {
                            "static_analysis_results": {
                                "vulnerability_id": first_correlation.get('vulnerability_id', ''),
                                "vulnerability_title": first_correlation.get('vulnerability_title', ''),
                                "vulnerability_type": "unknown",
                                "validation_status": first_correlation.get('status', 'INCONCLUSIVE').replace('CONFIRMADA', 'CONFIRMED').replace('NO_CONFIRMADA', 'NOT_FOUND').replace('PROBABLE', 'PARTIAL'),
                                "confidence_level": first_correlation.get('confidence', 'Low'),
                                "evidence": {
                                    "code_snippets": code_snippets,
                                    "analysis_summary": first_correlation.get('reasoning', 'Análisis completado')
                                }
                            }
                        }
                        return simplified_result
                    
                    return result
                except (json.JSONDecodeError, ValueError) as e:
                    # Si no es JSON válido, usar fallback
                    print(f"[WARNING] LLM response no es JSON válido: {e}")
                    print(f"[DEBUG] Respuesta del LLM: {response_text[:500]}...")
                    return self._fallback_correlation(semgrep_results, reported_vulnerabilities)
            else:
                # Fallback al método anterior si no hay LLM disponible
                return self._fallback_correlation(semgrep_results, reported_vulnerabilities)
                
        except Exception as e:
            return {"error": f"Error en análisis con LLM: {str(e)}"}
    
    def _generate_dynamic_rules(self, reported_vulnerabilities: List[Dict[str, Any]], target_path: str) -> List[str]:
        """Genera reglas de Semgrep dinámicamente usando LLM basándose en las vulnerabilidades reportadas"""
        import os
        
        dynamic_rules = []
        print(f"[DEBUG] Generando reglas dinámicas con LLM para {len(reported_vulnerabilities)} vulnerabilidades")
        print(f"[DEBUG] Target path: {target_path}")
        
        # Generar reglas para cada vulnerabilidad reportada usando LLM
        for vuln in reported_vulnerabilities:
            vuln_id = vuln.get('id', 'unknown')
            vuln_title = vuln.get('title', '')
            vuln_description = vuln.get('description', '')
            vuln_evidence = vuln.get('evidence', '')
            original_severity = vuln.get('severity', 'Medium').upper()
            
            print(f"[DEBUG] Procesando vulnerabilidad: {vuln_id} - {vuln_title}")
            
            # Generar regla usando LLM
            rule_content = self._generate_rule_with_llm(
                vuln_id=vuln_id,
                title=vuln_title,
                description=vuln_description,
                evidence=vuln_evidence,
                severity=original_severity
            )
            
            if rule_content:
                # Guardar regla en archivo temporal
                rule_file = os.path.join(target_path, f"dynamic_rule_{vuln_id}.yaml")
                print(f"[DEBUG] Guardando regla generada por LLM en: {rule_file}")
                try:
                    with open(rule_file, 'w') as f:
                        f.write(rule_content)
                    dynamic_rules.append(rule_file)
                except Exception as e:
                    print(f"[ERROR] No se pudo guardar la regla para {vuln_id}: {str(e)}")
            else:
                print(f"[WARNING] No se pudo generar regla para vulnerabilidad {vuln_id}")
        
        print(f"[DEBUG] Total de reglas dinámicas generadas: {len(dynamic_rules)}")
        return dynamic_rules
    
    def _generate_rule_with_llm(self, vuln_id: str, title: str, description: str, evidence: str, severity: str) -> str:
        """Genera una regla de Semgrep usando LLM basándose en la información de la vulnerabilidad"""
        try:
            if not hasattr(self, 'llm') or not self.llm:
                print(f"[WARNING] LLM no disponible para generar regla de {vuln_id}")
                return None
            
            # Convertir severidad al formato Semgrep
            semgrep_severity = self._convert_severity_to_semgrep(severity)
            
            # Crear prompt mejorado para generar la regla
            rule_generation_prompt = f"""
            Eres un experto en análisis de seguridad y creación de reglas de Semgrep. Tu tarea es generar una regla YAML de Semgrep específica para detectar la siguiente vulnerabilidad:
            
            INFORMACIÓN DE LA VULNERABILIDAD:
            - ID: {vuln_id}
            - Título: {title}
            - Descripción: {description}
            - Evidencia: {evidence}
            - Severidad: {severity}
            
            PATRONES DE EJEMPLO POR TIPO DE VULNERABILIDAD:
            
            PATH TRAVERSAL:
            - os.path.join($BASE, $USER_INPUT) donde $USER_INPUT viene de request.args/form
            - send_file(os.path.join(..., $USER_INPUT), ...)
            - open(os.path.join(..., $USER_INPUT), ...)
            - Buscar uso de '../' o '..' en rutas de archivos
            
            COMMAND INJECTION:
            - os.system($USER_INPUT)
            - subprocess.call($USER_INPUT)
            - eval($USER_INPUT)
            
            INSTRUCCIONES:
            1. Analiza el título y descripción para identificar el tipo de vulnerabilidad
            2. Crea los patrones apropiados según el tipo detectado
            3. Incluye múltiples variantes del patrón cuando sea posible
            4. Usa pattern-either para múltiples patrones alternativos
            5. Incluye pattern-not para reducir falsos positivos
            6. Asigna el CWE correcto según el tipo de vulnerabilidad
            
            
            FORMATO DE SALIDA:
            Retorna ÚNICAMENTE el contenido YAML de la regla, sin explicaciones adicionales.
            
            EJEMPLO GENÉRICO:
             ```yaml
             rules:
               - id: dynamic-{vuln_id}
                 patterns:
                   - pattern-either:
                       - pattern: |
                           $INPUT = request.args.get($KEY)
                           ...
                           $VULNERABLE_FUNCTION($INPUT, ...)
                       - pattern: |
                           $INPUT = request.form.get($KEY)
                           ...
                           $VULNERABLE_FUNCTION(..., $INPUT, ...)
                       - pattern: |
                           $VULNERABLE_FUNCTION($INPUT)
                 message: |
                   Potential vulnerability detected: [descripción específica basada en el tipo]
                 languages: [lenguaje detectado automáticamente]
                 severity: {semgrep_severity}
                 metadata:
                   category: security
                   cwe:
                     - "[CWE apropiado según el tipo de vulnerabilidad]"
                   confidence: HIGH
                   likelihood: HIGH
                   impact: HIGH
                   subcategory:
                     - vuln
             ```
            
            Genera la regla ahora basándote en la información proporcionada:
            """
            
            # Usar el LLM para generar la regla
            response = self.llm.invoke(rule_generation_prompt)
            
            # Extraer el contenido de la respuesta
            if hasattr(response, 'content'):
                rule_content = response.content
            else:
                rule_content = str(response)
            
            # Limpiar la respuesta para extraer solo el YAML
            rule_content = self._clean_yaml_response(rule_content)
            
            if rule_content and self._validate_yaml_rule(rule_content):
                print(f"[DEBUG] Regla generada exitosamente para {vuln_id}")
                return rule_content
            else:
                print(f"[ERROR] Regla generada inválida para {vuln_id}")
                return None
                
        except Exception as e:
            print(f"[ERROR] Error generando regla con LLM para {vuln_id}: {str(e)}")
            return None
    
    def _clean_yaml_response(self, response: str) -> str:
        """Limpia la respuesta del LLM para extraer solo el contenido YAML válido"""
        try:
            # Buscar bloques de código YAML
            import re
            
            # Buscar contenido entre ```yaml y ``` o ```yml y ```
            yaml_pattern = r'```(?:yaml|yml)\s*\n(.*?)\n```'
            match = re.search(yaml_pattern, response, re.DOTALL | re.IGNORECASE)
            
            if match:
                return match.group(1).strip()
            
            # Si no hay bloques de código, buscar contenido que empiece con 'rules:'
            rules_pattern = r'(rules:\s*\n.*?)(?=\n\n|$)'
            match = re.search(rules_pattern, response, re.DOTALL)
            
            if match:
                return match.group(1).strip()
            
            # Como último recurso, retornar la respuesta completa limpia
            lines = response.strip().split('\n')
            yaml_lines = []
            in_yaml = False
            
            for line in lines:
                if line.strip().startswith('rules:'):
                    in_yaml = True
                if in_yaml:
                    yaml_lines.append(line)
            
            return '\n'.join(yaml_lines) if yaml_lines else response.strip()
            
        except Exception as e:
            print(f"[ERROR] Error limpiando respuesta YAML: {str(e)}")
            return response.strip()
    
    def _validate_yaml_rule(self, yaml_content: str) -> bool:
        """Valida que el contenido YAML sea una regla de Semgrep válida"""
        try:
            import yaml
            
            # Intentar parsear el YAML
            parsed = yaml.safe_load(yaml_content)
            
            # Verificar estructura básica
            if not isinstance(parsed, dict):
                return False
            
            if 'rules' not in parsed:
                return False
            
            rules = parsed['rules']
            if not isinstance(rules, list) or len(rules) == 0:
                return False
            
            # Verificar que cada regla tenga los campos mínimos requeridos
            for rule in rules:
                if not isinstance(rule, dict):
                    return False
                
                required_fields = ['id', 'message', 'languages', 'severity']
                for field in required_fields:
                    if field not in rule:
                        return False
                
                # Verificar que tenga al menos un patrón
                if 'patterns' not in rule and 'pattern' not in rule:
                    return False
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Error validando YAML: {str(e)}")
            return False
    
    def _convert_severity_to_semgrep(self, original_severity: str) -> str:
        """Convierte la severidad del reporte al formato de Semgrep"""
        severity_mapping = {
            'CRITICAL': 'ERROR',
            'HIGH': 'ERROR', 
            'MEDIUM': 'WARNING',
            'LOW': 'INFO',
            'INFORMATIONAL': 'INFO'
        }
        return severity_mapping.get(original_severity, 'WARNING')
    

    
    def _fallback_correlation(self, semgrep_results: Dict[str, Any], reported_vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Método de fallback simplificado para correlación cuando el LLM no está disponible"""
        try:
            semgrep_findings = semgrep_results.get('results', [])
            
            # Tomar la primera vulnerabilidad reportada
            if not reported_vulnerabilities:
                return {
                    "static_analysis_results": {
                        "vulnerability_id": "unknown",
                        "vulnerability_title": "No vulnerabilities reported",
                        "vulnerability_type": "unknown",
                        "validation_status": "NOT_FOUND",
                        "confidence_level": "Low",
                        "evidence": {
                            "code_snippets": [],
                            "analysis_summary": "No se reportaron vulnerabilidades para analizar"
                        }
                    }
                }
            
            vuln = reported_vulnerabilities[0]
            
            # Buscar hallazgos relevantes
            code_snippets = []
            for finding in semgrep_findings[:3]:  # Limitar a 3 hallazgos
                code_snippets.append({
                    "file_path": finding.get('path', ''),
                    "line_numbers": str(finding.get('start', {}).get('line', '')),
                    "vulnerable_code": finding.get('extra', {}).get('lines', ''),
                    "vulnerability_pattern": finding.get('message', '')
                })
            
            # Determinar status basado en hallazgos
            if code_snippets:
                validation_status = "PARTIAL"
                confidence_level = "Medium"
                analysis_summary = f"Se encontraron {len(code_snippets)} hallazgos potencialmente relacionados"
            else:
                validation_status = "NOT_FOUND"
                confidence_level = "Low"
                analysis_summary = "No se encontraron hallazgos específicos en el análisis estático"
            
            return {
                "static_analysis_results": {
                    "vulnerability_id": vuln.get('id', 'unknown'),
                    "vulnerability_title": vuln.get('title', vuln.get('name', 'Unknown')),
                    "vulnerability_type": vuln.get('type', 'unknown'),
                    "validation_status": validation_status,
                    "confidence_level": confidence_level,
                    "evidence": {
                        "code_snippets": code_snippets,
                        "analysis_summary": analysis_summary
                    }
                }
            }
            
        except Exception as e:
            return {
                "static_analysis_results": {
                    "vulnerability_id": "error",
                    "vulnerability_title": "Error en análisis",
                    "vulnerability_type": "unknown",
                    "validation_status": "INCONCLUSIVE",
                    "confidence_level": "Low",
                    "evidence": {
                        "code_snippets": [],
                        "analysis_summary": f"Error en correlación de fallback: {str(e)}"
                    }
                }
            }
    
    def _extract_file_paths(self, text: str) -> List[str]:
        """Extrae rutas de archivos del texto de evidencia"""
        import re
        
        # Patrones para detectar rutas de archivos
        file_patterns = [
            r'[\w\-_./\\]+\.[a-zA-Z]{2,4}',  # archivos con extensión
            r'/[\w\-_./]+',  # rutas Unix
            r'[A-Za-z]:\\[\w\-_.\\]+',  # rutas Windows
        ]
        
        file_paths = []
        for pattern in file_patterns:
            matches = re.findall(pattern, text)
            file_paths.extend(matches)
        
        # Limpiar y filtrar rutas válidas
        cleaned_paths = []
        for path in file_paths:
            # Filtrar rutas muy cortas o que parezcan URLs
            if len(path) > 3 and not path.startswith('http') and not path.startswith('www'):
                cleaned_paths.append(path.strip())
        
        return list(set(cleaned_paths))  # Eliminar duplicados
    
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
        """Templates de comandos Semgrep para el enfoque dinámico"""
        return {
            "generic_scan": "semgrep --config=auto --json --verbose",
            "comprehensive": "semgrep --config=auto --json --verbose",
            "security_focused": "semgrep --config=p/security-audit --json --verbose",
            "owasp_top10": "semgrep --config=p/owasp-top-ten --json --verbose",
            "language_specific": "semgrep --config=p/{language} --json --verbose"
        }
    
    def get_correlation_strategies(self) -> Dict[str, str]:
        """Estrategias de correlación entre hallazgos y vulnerabilidades reportadas"""
        return {
            "llm_analysis": "Análisis inteligente por LLM para correlación contextual",
            "semantic_matching": "Coincidencia semántica entre tipos de vulnerabilidad",
            "code_pattern_analysis": "Análisis de patrones de código y funciones",
            "location_correlation": "Correlación por ubicación de archivos y líneas",
            "evidence_matching": "Coincidencia con evidencia específica del reporte",
            "contextual_reasoning": "Razonamiento contextual y explicaciones detalladas"
        }
    
    def get_dynamic_analysis_workflow(self) -> Dict[str, str]:
        """Flujo de trabajo para análisis dinámico con LLM"""
        return {
            "step_1": "Ejecutar escaneo genérico completo con Semgrep usando config=auto",
            "step_2": "Preparar contexto con vulnerabilidades reportadas y hallazgos de Semgrep",
            "step_3": "Usar LLM para análisis inteligente y correlación contextual",
            "step_4": "Generar correlaciones con razonamiento detallado por cada vulnerabilidad",
            "step_5": "Aplicar fallback automático si el LLM no está disponible",
            "step_6": "Retornar análisis estructurado con evidencia y explicaciones"
        }