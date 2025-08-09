#!/usr/bin/env python3
"""
Herramienta para ejecutar análisis dinámico con Nuclei
Utilizada por el agente dinámico para validar vulnerabilidades en aplicaciones web
"""

import os
import json
import subprocess
import tempfile
from typing import Dict, Any, List, Optional
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import logging
import yaml

class NucleiInput(BaseModel):
    """Input schema para la herramienta de Nuclei"""
    target: str = Field(description="URL o host objetivo para el análisis")
    templates: Optional[List[str]] = Field(default=None, description="Lista de templates específicos a usar")
    tags: Optional[List[str]] = Field(default=None, description="Tags de templates a incluir (ej: sqli, xss, rce)")
    severity: Optional[List[str]] = Field(default=None, description="Severidades a incluir (critical, high, medium, low, info)")
    custom_template: Optional[str] = Field(default=None, description="Template personalizado en formato YAML")
    timeout: Optional[int] = Field(default=10, description="Timeout por request en segundos")
    rate_limit: Optional[int] = Field(default=150, description="Requests por segundo")
    exclude_tags: Optional[List[str]] = Field(default=None, description="Tags a excluir")

class NucleiTool(BaseTool):
    """Herramienta para ejecutar análisis dinámico con Nuclei"""
    
    name: str = "Nuclei Dynamic Scanner"
    description: str = """
    Ejecuta análisis dinámico de vulnerabilidades usando Nuclei contra aplicaciones web.
    Puede usar templates específicos, filtrar por tags/severidad, y crear templates personalizados.
    Retorna resultados estructurados con detalles de vulnerabilidades encontradas.
    """
    args_schema: type[BaseModel] = NucleiInput
    
    def _run(self, target: str, templates: Optional[List[str]] = None,
             tags: Optional[List[str]] = None, severity: Optional[List[str]] = None,
             custom_template: Optional[str] = None, timeout: int = 10,
             rate_limit: int = 150, exclude_tags: Optional[List[str]] = None) -> str:
        """Ejecuta el análisis con Nuclei"""
        logger = logging.getLogger(__name__)
        try:
            # Validar target
            if not self._validate_target(target):
                return f"Error: Target inválido {target}"
            
            # Verificar si Nuclei está instalado
            if not self._check_nuclei_installed():
                return "Error: Nuclei no está instalado. Descárgalo desde https://github.com/projectdiscovery/nuclei"
            
            # Manejar template personalizado
            custom_template_path = None
            if custom_template:
                custom_template_path = self._create_custom_template(custom_template)
            
            # Construir comando de Nuclei
            cmd = self._build_nuclei_command(target, templates, tags, severity, 
                                           custom_template_path, timeout, rate_limit, exclude_tags)
            
            # Ejecutar Nuclei
            result = self._execute_nuclei(cmd)
            
            # Limpiar archivo temporal si se creó
            if custom_template_path and os.path.exists(custom_template_path):
                os.unlink(custom_template_path)
            
            # Procesar y formatear resultados
            return self._format_results(result, target)
            
        except Exception as e:
            logger.error(f"Error ejecutando Nuclei: {str(e)}")
            return f"Error en análisis dinámico: {str(e)}"
    
    def _validate_target(self, target: str) -> bool:
        """Valida que el target sea una URL o host válido"""
        if not target:
            return False
        
        # Agregar protocolo si no lo tiene
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        return True
    
    def _check_nuclei_installed(self) -> bool:
        """Verifica si Nuclei está instalado"""
        try:
            subprocess.run(["nuclei", "-version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _create_custom_template(self, template_content: str) -> str:
        """Crea un archivo temporal con el template personalizado"""
        try:
            # Validar que sea YAML válido
            yaml.safe_load(template_content)
            
            # Crear archivo temporal
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(template_content)
                return f.name
                
        except yaml.YAMLError as e:
            raise Exception(f"Template YAML inválido: {str(e)}")
        except Exception as e:
            raise Exception(f"Error creando template personalizado: {str(e)}")
    
    def _build_nuclei_command(self, target: str, templates: Optional[List[str]],
                             tags: Optional[List[str]], severity: Optional[List[str]],
                             custom_template_path: Optional[str], timeout: int,
                             rate_limit: int, exclude_tags: Optional[List[str]]) -> List[str]:
        """Construye el comando de Nuclei"""
        cmd = ["nuclei", "-json", "-silent"]
        
        # Target
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        cmd.extend(["-target", target])
        
        # Templates específicos
        if templates:
            for template in templates:
                cmd.extend(["-t", template])
        elif custom_template_path:
            cmd.extend(["-t", custom_template_path])
        
        # Tags
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        
        # Severidad
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        
        # Tags a excluir
        if exclude_tags:
            cmd.extend(["-exclude-tags", ",".join(exclude_tags)])
        
        # Configuraciones de rendimiento
        cmd.extend(["-timeout", str(timeout)])
        cmd.extend(["-rate-limit", str(rate_limit)])
        
        # Configuraciones adicionales
        cmd.extend(["-no-color", "-no-update-check"])
        
        return cmd
    
    def _execute_nuclei(self, cmd: List[str]) -> List[Dict[str, Any]]:
        """Ejecuta el comando de Nuclei"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            results = []
            if result.stdout:
                # Nuclei retorna una línea JSON por cada hallazgo
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            
            return results
                
        except subprocess.TimeoutExpired:
            raise Exception("Timeout ejecutando Nuclei (10 minutos)")
        except Exception as e:
            raise Exception(f"Error ejecutando comando Nuclei: {str(e)}")
    
    def _format_results(self, nuclei_results: List[Dict[str, Any]], target: str) -> str:
        """Formatea los resultados de Nuclei para el agente"""
        formatted_parts = []
        
        # Resumen ejecutivo
        formatted_parts.append("=== RESUMEN DE ANÁLISIS DINÁMICO ===")
        formatted_parts.append(f"Target analizado: {target}")
        formatted_parts.append(f"Total de hallazgos: {len(nuclei_results)}")
        
        # Agrupar por severidad
        severity_counts = {}
        for result in nuclei_results:
            severity = result.get("info", {}).get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts:
            formatted_parts.append("\nDistribución por severidad:")
            severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
            for severity in severity_order:
                if severity in severity_counts:
                    formatted_parts.append(f"  {severity.upper()}: {severity_counts[severity]}")
        
        # Agrupar por categoría/tags
        tag_counts = {}
        for result in nuclei_results:
            tags = result.get("info", {}).get("tags", [])
            for tag in tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
        
        if tag_counts:
            formatted_parts.append("\nCategorías de vulnerabilidades:")
            sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            for tag, count in sorted_tags:
                formatted_parts.append(f"  {tag}: {count}")
        
        # Detalles de hallazgos
        if nuclei_results:
            formatted_parts.append("\n=== HALLAZGOS DETALLADOS ===")
            
            for i, result in enumerate(nuclei_results, 1):
                formatted_parts.append(f"\n--- HALLAZGO {i} ---")
                
                # Información básica
                template_id = result.get("template-id", "N/A")
                info = result.get("info", {})
                name = info.get("name", "N/A")
                severity = info.get("severity", "N/A")
                tags = info.get("tags", [])
                
                formatted_parts.append(f"Template: {template_id}")
                formatted_parts.append(f"Nombre: {name}")
                formatted_parts.append(f"Severidad: {severity.upper()}")
                if tags:
                    formatted_parts.append(f"Tags: {', '.join(tags)}")
                
                # URL y método
                matched_at = result.get("matched-at", "N/A")
                formatted_parts.append(f"URL: {matched_at}")
                
                # Tipo de matcher
                matcher_status = result.get("matcher-status", False)
                formatted_parts.append(f"Match confirmado: {'Sí' if matcher_status else 'No'}")
                
                # Descripción
                description = info.get("description", "")
                if description:
                    formatted_parts.append(f"Descripción: {description}")
                
                # Referencias
                references = info.get("reference", [])
                if references:
                    formatted_parts.append(f"Referencias: {', '.join(references[:3])}")
                
                # Clasificación
                classification = info.get("classification", {})
                if classification:
                    if "cwe-id" in classification:
                        formatted_parts.append(f"CWE: {classification['cwe-id']}")
                    if "cvss-score" in classification:
                        formatted_parts.append(f"CVSS Score: {classification['cvss-score']}")
                
                # Extracted data si existe
                extracted_results = result.get("extracted-results", [])
                if extracted_results:
                    formatted_parts.append(f"Datos extraídos: {', '.join(extracted_results[:3])}")
        
        # Recomendaciones
        formatted_parts.append("\n=== RECOMENDACIONES ===")
        if not nuclei_results:
            formatted_parts.append("✅ No se encontraron vulnerabilidades con los templates aplicados.")
        else:
            critical_high = [r for r in nuclei_results 
                           if r.get("info", {}).get("severity") in ["critical", "high"]]
            if critical_high:
                formatted_parts.append(f"🔴 {len(critical_high)} vulnerabilidades críticas/altas requieren atención inmediata.")
            
            medium = [r for r in nuclei_results 
                     if r.get("info", {}).get("severity") == "medium"]
            if medium:
                formatted_parts.append(f"🟡 {len(medium)} vulnerabilidades medias deben ser priorizadas.")
            
            # Sugerencias específicas por tipo
            sqli_results = [r for r in nuclei_results 
                          if any("sql" in tag.lower() for tag in r.get("info", {}).get("tags", []))]
            if sqli_results:
                formatted_parts.append("💉 Se detectaron posibles SQL Injections - implementar prepared statements.")
            
            xss_results = [r for r in nuclei_results 
                         if any("xss" in tag.lower() for tag in r.get("info", {}).get("tags", []))]
            if xss_results:
                formatted_parts.append("🔗 Se detectaron posibles XSS - implementar sanitización de entrada.")
        
        return "\n".join(formatted_parts)