#!/usr/bin/env python3
"""
Herramienta para ejecutar análisis estático con Semgrep
Utilizada por el agente estático para validar vulnerabilidades en código fuente
"""

import os
import json
import subprocess
from typing import Dict, Any, List, Optional
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import logging

class SemgrepInput(BaseModel):
    """Input schema para la herramienta de Semgrep"""
    target_path: str = Field(description="Ruta del directorio o archivo a analizar")
    rules: Optional[List[str]] = Field(default=None, description="Lista de reglas específicas a usar")
    config: Optional[str] = Field(default="auto", description="Configuración de reglas (auto, p/security-audit, etc.)")
    language: Optional[str] = Field(default=None, description="Lenguaje específico a analizar")
    severity: Optional[str] = Field(default=None, description="Filtrar por severidad (ERROR, WARNING, INFO)")
    exclude_patterns: Optional[List[str]] = Field(default=None, description="Patrones de archivos a excluir")

class SemgrepTool(BaseTool):
    """Herramienta para ejecutar análisis estático con Semgrep"""
    
    name: str = "Semgrep Static Analyzer"
    description: str = """
    Ejecuta análisis estático de código usando Semgrep para detectar vulnerabilidades de seguridad.
    Puede usar reglas específicas, configuraciones predefinidas, y filtrar por lenguaje o severidad.
    Retorna resultados estructurados en formato JSON con detalles de vulnerabilidades encontradas.
    """
    args_schema: type[BaseModel] = SemgrepInput
    
    def _run(self, target_path: str, rules: Optional[List[str]] = None, 
             config: str = "auto", language: Optional[str] = None,
             severity: Optional[str] = None, exclude_patterns: Optional[List[str]] = None) -> str:
        """Ejecuta el análisis con Semgrep"""
        logger = logging.getLogger(__name__)
        try:
            if not os.path.exists(target_path):
                return f"Error: La ruta {target_path} no existe"
            
            # Verificar si Semgrep está instalado
            if not self._check_semgrep_installed():
                return "Error: Semgrep no está instalado. Instálalo con: pip install semgrep"
            
            # Construir comando de Semgrep
            cmd = self._build_semgrep_command(target_path, rules, config, language, severity, exclude_patterns)
            
            # Ejecutar Semgrep
            result = self._execute_semgrep(cmd)
            
            # Procesar y formatear resultados
            return self._format_results(result)
            
        except Exception as e:
            logger.error(f"Error ejecutando Semgrep: {str(e)}")
            return f"Error en análisis estático: {str(e)}"
    
    def _check_semgrep_installed(self) -> bool:
        """Verifica si Semgrep está instalado"""
        try:
            subprocess.run(["semgrep", "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _build_semgrep_command(self, target_path: str, rules: Optional[List[str]], 
                              config: str, language: Optional[str], 
                              severity: Optional[str], exclude_patterns: Optional[List[str]]) -> List[str]:
        """Construye el comando de Semgrep"""
        cmd = ["semgrep", "--json", "--no-git-ignore"]
        
        # Configuración de reglas
        if rules:
            for rule in rules:
                cmd.extend(["--config", rule])
        elif config:
            cmd.extend(["--config", config])
        
        # Filtro por lenguaje
        if language:
            cmd.extend(["--lang", language])
        
        # Filtro por severidad
        if severity:
            cmd.extend(["--severity", severity])
        
        # Patrones de exclusión
        if exclude_patterns:
            for pattern in exclude_patterns:
                cmd.extend(["--exclude", pattern])
        
        # Ruta objetivo
        cmd.append(target_path)
        
        return cmd
    
    def _execute_semgrep(self, cmd: List[str]) -> Dict[str, Any]:
        """Ejecuta el comando de Semgrep"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                return json.loads(result.stdout)
            else:
                return {"results": [], "errors": [result.stderr] if result.stderr else []}
                
        except subprocess.TimeoutExpired:
            raise Exception("Timeout ejecutando Semgrep (5 minutos)")
        except json.JSONDecodeError as e:
            raise Exception(f"Error parseando salida JSON de Semgrep: {str(e)}")
        except Exception as e:
            raise Exception(f"Error ejecutando comando Semgrep: {str(e)}")
    
    def _format_results(self, semgrep_output: Dict[str, Any]) -> str:
        """Formatea los resultados de Semgrep para el agente"""
        results = semgrep_output.get("results", [])
        errors = semgrep_output.get("errors", [])
        
        formatted_parts = []
        
        # Resumen ejecutivo
        formatted_parts.append("=== RESUMEN DE ANÁLISIS ESTÁTICO ===")
        formatted_parts.append(f"Total de hallazgos: {len(results)}")
        
        if errors:
            formatted_parts.append(f"Errores durante el análisis: {len(errors)}")
        
        # Agrupar por severidad
        severity_counts = {}
        for result in results:
            severity = result.get("extra", {}).get("severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts:
            formatted_parts.append("\nDistribución por severidad:")
            for severity, count in sorted(severity_counts.items()):
                formatted_parts.append(f"  {severity}: {count}")
        
        # Detalles de hallazgos
        if results:
            formatted_parts.append("\n=== HALLAZGOS DETALLADOS ===")
            
            for i, result in enumerate(results, 1):
                formatted_parts.append(f"\n--- HALLAZGO {i} ---")
                
                # Información básica
                rule_id = result.get("check_id", "N/A")
                message = result.get("extra", {}).get("message", "N/A")
                severity = result.get("extra", {}).get("severity", "N/A")
                
                formatted_parts.append(f"Regla: {rule_id}")
                formatted_parts.append(f"Mensaje: {message}")
                formatted_parts.append(f"Severidad: {severity}")
                
                # Ubicación
                path = result.get("path", "N/A")
                start_line = result.get("start", {}).get("line", "N/A")
                end_line = result.get("end", {}).get("line", "N/A")
                
                formatted_parts.append(f"Archivo: {path}")
                formatted_parts.append(f"Líneas: {start_line}-{end_line}")
                
                # Código afectado
                if "extra" in result and "lines" in result["extra"]:
                    lines = result["extra"]["lines"]
                    formatted_parts.append(f"Código:\n{lines}")
                
                # Metadatos adicionales
                extra = result.get("extra", {})
                if "metadata" in extra:
                    metadata = extra["metadata"]
                    if "cwe" in metadata:
                        formatted_parts.append(f"CWE: {metadata['cwe']}")
                    if "owasp" in metadata:
                        formatted_parts.append(f"OWASP: {metadata['owasp']}")
                    if "references" in metadata:
                        refs = metadata["references"]
                        if refs:
                            formatted_parts.append(f"Referencias: {', '.join(refs[:3])}")
        
        # Errores si los hay
        if errors:
            formatted_parts.append("\n=== ERRORES DURANTE EL ANÁLISIS ===")
            for error in errors:
                formatted_parts.append(f"- {error}")
        
        # Recomendaciones
        formatted_parts.append("\n=== RECOMENDACIONES ===")
        if not results:
            formatted_parts.append("✅ No se encontraron vulnerabilidades con las reglas aplicadas.")
        else:
            high_severity = [r for r in results if r.get("extra", {}).get("severity") == "ERROR"]
            if high_severity:
                formatted_parts.append(f"🔴 {len(high_severity)} hallazgos de alta severidad requieren atención inmediata.")
            
            medium_severity = [r for r in results if r.get("extra", {}).get("severity") == "WARNING"]
            if medium_severity:
                formatted_parts.append(f"🟡 {len(medium_severity)} hallazgos de severidad media deben ser revisados.")
        
        return "\n".join(formatted_parts)