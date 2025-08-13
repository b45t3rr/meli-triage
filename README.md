# 🛡️ Sistema de Validación de Vulnerabilidades con IA

> **Sistema inteligente de análisis triage de vulnerabilidades que combina extracción de PDF, análisis estático y dinámico usando agentes de IA especializados con soporte multi-LLM**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![CrewAI](https://img.shields.io/badge/CrewAI-Latest-green.svg)](https://crewai.com)
[![Multi-LLM](https://img.shields.io/badge/Multi--LLM-7%20Providers-orange.svg)](#-soporte-multi-llm)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🎯 ¿Qué hace este sistema?

Este sistema automatiza la validación de vulnerabilidades de seguridad mediante un enfoque de **múltiples agentes de IA** que trabajan en conjunto:

1. **📄 Extrae** vulnerabilidades de reportes PDF
2. **🔍 Analiza** código fuente estáticamente con Semgrep
3. **🎯 Prueba** aplicaciones dinámicamente con curl y nmap
4. **📊 Consolida** resultados en un reporte final inteligente

## ✨ Características Principales

### 🤖 Soporte Multi-LLM
Compatible con **7 proveedores** y **30+ modelos** de IA del mercado:

| Proveedor | Modelos Disponibles | Modelo por Defecto |
|-----------|-------------------|-------------------|
| **🤖 OpenAI** | GPT-5, GPT-5-mini, GPT-4o, GPT-4o-mini, O1, O1-mini, GPT-4-turbo | `gpt-4o-mini` |
| **🧠 Anthropic** | Claude 3.5 Sonnet, Claude 3.5 Haiku, Claude 3.7 Sonnet, Claude 3 Opus | `claude-3-5-sonnet-20241022` |
| **🌟 Google** | Gemini 2.5 Flash, Gemini 2.0 Flash, Gemini 1.5 Pro/Flash | `gemini-2.5-flash` |
| **🔥 DeepSeek** | DeepSeek Chat, DeepSeek Coder, DeepSeek Reasoner | `deepseek-chat` |
| **⚡ Groq** | Llama 3.3 70B, Llama 3.1 70B/8B, Mixtral 8x7B, Gemma2 9B | `llama-3.3-70b-versatile` |
| **🎯 Mistral** | Mistral Large/Medium/Small, Open-Mistral 7B, Open-Mixtral 8x7B | `mistral-large-latest` |
| **🚀 xAI** | Grok Beta, Grok-3, Grok-3-mini, Grok-4 Beta | `grok-beta` |

### 🏗️ Arquitectura de 4 Agentes Especializados

| Agente | Función | Herramientas | Especialidad |
|--------|---------|-------------|-------------|
| 🔍 **Extractor** | Analiza PDFs | PyPDF2 + LLM | Categorización automática con CWE/OWASP Top 10 |
| 🔧 **Estático** | Análisis de código | Semgrep + LLM | Correlación de vulnerabilidades en código fuente |
| 🎯 **Dinámico** | Pruebas en vivo | curl + nmap + GenericLinuxCommand | Payloads generados por LLM y testing automatizado |
| 📊 **Triage** | Consolidación | LLM Multi-Provider | Validación cruzada y reclasificación inteligente |

### 🚀 Modos de Ejecución Flexibles
- **Completo**: Análisis end-to-end
- **Solo extracción**: Procesar únicamente PDFs
- **Solo estático**: Análisis de código fuente
- **Solo dinámico**: Pruebas en aplicaciones web

## 📦 Instalación Rápida

### Prerrequisitos
```bash
# Python 3.8 o superior
python --version

# Git (para clonar el repositorio)
git --version
```

### 1. Clonar e Instalar
```bash
# Clonar el repositorio
git clone <repository-url>
cd test3

# Instalar dependencias de Python
pip install -r requirements.txt

# Las herramientas de análisis ya están incluidas en requirements.txt
# Verificar instalación de Semgrep
semgrep --version
```

### 2. Instalar herramientas del sistema
```bash
# Instalar nmap (para análisis dinámico)
sudo apt-get install nmap

# Verificar herramientas preinstaladas
curl --version    # HTTP testing
nmap --version    # Network scanning
python3 --version # Python 3.8+
```

### 3. Configurar API Keys
```bash
# Crear archivo .env con las claves que necesites
cat > .env << EOF
# OpenAI (requerido por defecto)
OPENAI_API_KEY=sk-tu-api-key-aqui

# Proveedores adicionales (opcional)
ANTHROPIC_API_KEY=sk-ant-tu-api-key
GOOGLE_API_KEY=AI-tu-api-key
DEEPSEEK_API_KEY=sk-tu-api-key
GROQ_API_KEY=gsk_tu-api-key
MISTRAL_API_KEY=tu-api-key
XAI_API_KEY=tu-api-key

# MongoDB (opcional)
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=vulnerability_db
EOF

# O exportar como variables de entorno
export OPENAI_API_KEY="sk-tu-api-key-aqui"
```

## 🚀 Uso

### Comando Básico
```bash
# Análisis completo
python main.py --pdf reporte.pdf --source ./codigo --url https://ejemplo.com
```

### Ejemplos Prácticos

#### 📄 Solo Extracción de PDF
```bash
python main.py --pdf vulnerability_report.pdf --extract-only
```

#### 🔍 Solo Análisis Estático
```bash
python main.py --pdf report.pdf --source ./src --static-only
```

#### 🎯 Solo Análisis Dinámico
```bash
python main.py --pdf report.pdf --url https://app.ejemplo.com --dynamic-only
```

#### 🤖 Usar Modelo Específico
```bash
# OpenAI GPT-4o
python main.py --model gpt-4o --pdf report.pdf --extract-only

# Anthropic Claude 3.5 Sonnet
python main.py --model claude-3-5-sonnet-20241022 --pdf report.pdf --source ./src --url https://app.com

# Google Gemini 2.5 Flash
python main.py --model gemini-2.5-flash --pdf report.pdf --static-only --source ./code

# DeepSeek Chat
python main.py --model deepseek-chat --pdf report.pdf --dynamic-only --url https://app.com

# Groq Llama 3.3
python main.py --model llama-3.3-70b-versatile --pdf report.pdf --source ./src

# Mistral Large
python main.py --model mistral-large-latest --pdf report.pdf --extract-only

# xAI Grok
python main.py --model grok-beta --pdf report.pdf --source ./src --url https://app.com
```

#### 💾 Guardar Resultados
```bash
python main.py --pdf report.pdf --source ./src --url https://app.com --save-output --output ./mis_resultados
```

### Ver Modelos Disponibles
```bash
python main.py --list-models
```

### Ayuda Completa
```bash
python main.py --help
```

## 📊 Resultados y Salidas

El sistema genera archivos estructurados en el directorio `results/` con timestamps únicos:

```
results/
├── validation_result_YYYYMMDD_HHMMSS.json    # Resultado consolidado final
├── extraction_YYYYMMDD_HHMMSS.json           # Vulnerabilidades extraídas del PDF
├── static_analysis_YYYYMMDD_HHMMSS.json      # Resultados de análisis estático (Semgrep)
├── dynamic_analysis_YYYYMMDD_HHMMSS.json     # Resultados de análisis dinámico (curl/nmap)
└── final_report_YYYYMMDD_HHMMSS.json         # Reporte final de triage y validación
```

### 📁 Estructura de Archivos por Modo
- **Modo completo**: Genera todos los archivos arriba
- **Solo extracción**: `extraction_*.json`
- **Solo estático**: `extraction_*.json` + `static_analysis_*.json`
- **Solo dinámico**: `extraction_*.json` + `dynamic_analysis_*.json`

### Estructura de Salida JSON
```json
{
  "extraction_results": {
    "vulnerabilities": [
      {
        "title": "SQL Injection en formulario de login",
        "cwe": "CWE-89",
        "owasp_category": "A03:2021 – Injection",
        "severity": "High",
        "description": "Vulnerabilidad de inyección SQL en parámetro 'username'",
        "location": "login.php línea 45",
        "impact": "Acceso no autorizado a base de datos",
        "recommendation": "Usar prepared statements"
      }
    ],
    "summary": {
      "total_vulnerabilities": 5,
      "by_severity": {"Critical": 1, "High": 2, "Medium": 2},
      "by_category": {"Injection": 2, "XSS": 2, "CSRF": 1}
    }
  },
  "static_analysis_results": {
    "semgrep_findings": [...],
    "code_correlations": [...]
  },
  "dynamic_analysis_results": {
    "curl_tests": [...],
    "nmap_scans": [...],
    "payload_results": [...]
  },
  "final_triage_report": {
    "validated_vulnerabilities": [...],
    "false_positives": [...],
    "new_findings": [...],
    "recommendations": [...],
    "risk_assessment": "High"
  },
  "metadata": {
    "analysis_date": "2024-01-15T10:30:00Z",
    "model_used": "gpt-4o-mini",
    "execution_time": "45.2s",
    "version": "1.0.0",
    "modes_executed": ["extraction", "static", "dynamic", "triage"]
  }
}
```

## 🏗️ Estructura del Proyecto

```
test3/
├── 🤖 agents/                 # Agentes de IA especializados
│   ├── extractor_agent.py     # Extracción y categorización de PDF
│   ├── static_agent.py        # Análisis estático con Semgrep
│   ├── dynamic_agent.py       # Análisis dinámico con curl/nmap
│   └── triage_agent.py        # Consolidación y triage inteligente
├── 🛠️ tools/                  # Herramientas especializadas
│   ├── pdf_tool.py            # Extracción de texto de PDF
│   ├── semgrep_tool.py        # Interfaz con Semgrep
│   └── generic_linux_command_tool.py # Herramienta unificada para curl, nmap, etc.
├── 📋 tasks/                  # Definiciones de tareas
│   ├── extraction_task.py     # Tarea de extracción
│   ├── static_analysis_task.py # Tarea de análisis estático
│   ├── dynamic_analysis_task.py # Tarea de análisis dinámico
│   └── triage_task.py         # Tarea de triage
├── ⚙️ config/                 # Configuraciones
│   └── llm_config.py          # Configuración multi-LLM
├── 🗄️ database/               # Conectores de base de datos
│   ├── mongodb_client.py      # Cliente MongoDB
│   └── mongodb_utils.py       # Utilidades MongoDB
├── 🐳 docker-compose.yml      # Configuración Docker
├── 📄 main.py                 # Punto de entrada principal
├── 📦 requirements.txt        # Dependencias Python
└── 📚 README.md              # Este archivo
```

## ⚡ Características Avanzadas

### 🎯 Selección Inteligente de Modelos
El sistema permite usar diferentes modelos según el tipo de análisis:

```bash
# Usar modelos especializados por tarea
python main.py \
  --pdf report.pdf \
  --source ./code \
  --url https://app.com \
  --model-extraction gpt-4o \
  --model-static deepseek-coder \
  --model-dynamic claude-3-5-sonnet-20241022 \
  --model-triage gpt-4o-mini
```

### 🔄 Modo de Validación Cruzada
```bash
# Usar múltiples modelos para validación cruzada
python main.py \
  --pdf report.pdf \
  --cross-validation \
  --models gpt-4o,claude-3-5-sonnet-20241022,gemini-2.5-flash
```

### 📊 Integración con MongoDB
```bash
# Guardar resultados en MongoDB para análisis histórico
export MONGODB_URI="mongodb://localhost:27017"
export MONGODB_DATABASE="security_analysis"

python main.py \
  --pdf report.pdf \
  --source ./code \
  --url https://app.com \
  --use-mongodb \
  --collection-name "q4_2024_analysis"
```

### 🎨 Formatos de Salida Personalizados
```bash
# Generar reportes en diferentes formatos
python main.py \
  --pdf report.pdf \
  --source ./code \
  --output-format json,html,csv \
  --template custom_template.html
```

## 🔧 Configuración Avanzada

### Variables de Entorno
```bash
# APIs de LLM (configura solo los que vayas a usar)
OPENAI_API_KEY=sk-...                    # OpenAI GPT models
ANTHROPIC_API_KEY=sk-ant-...             # Claude models  
GOOGLE_API_KEY=AI...                     # Gemini models
DEEPSEEK_API_KEY=sk-...                  # DeepSeek models
GROQ_API_KEY=gsk_...                     # Groq models (Llama, Mixtral)
MISTRAL_API_KEY=...                      # Mistral models
XAI_API_KEY=...                          # xAI Grok models

# Base de datos (opcional)
MONGODB_URI=mongodb://localhost:27017    # URI de MongoDB
MONGODB_DATABASE=vulnerability_db        # Nombre de la base de datos

# Configuraciones del sistema
LOG_LEVEL=INFO                           # Nivel de logging
OUTPUT_FORMAT=json                       # Formato de salida
```

### 🤖 Personalización de Agentes

Cada agente puede ser personalizado para casos de uso específicos:

```python
# agents/extractor_agent.py - Personalización para compliance
self.agent = Agent(
    role="Especialista en Compliance de Seguridad",
    goal="Extraer vulnerabilidades enfocándose en cumplimiento PCI-DSS y SOX",
    backstory="""Eres un auditor de seguridad especializado en compliance 
    financiero con experiencia en PCI-DSS, SOX y regulaciones bancarias.""",
    tools=[self.pdf_tool],
    llm=self.llm,
    max_iter=3,
    memory=True
)
```

### 🎛️ Configuración de Temperatura por Agente
```python
# config/agent_config.py
AGENT_CONFIGS = {
    "extractor": {"temperature": 0.1, "max_tokens": 4000},
    "static": {"temperature": 0.2, "max_tokens": 6000},
    "dynamic": {"temperature": 0.3, "max_tokens": 5000},
    "triage": {"temperature": 0.1, "max_tokens": 8000}
}
```

### 🔒 Configuración de Seguridad
```bash
# Configurar límites de seguridad
export MAX_FILE_SIZE_MB=50
export ALLOWED_DOMAINS="empresa.com,staging.empresa.com"
export SEMGREP_TIMEOUT=300
export NMAP_MAX_PORTS=1000
```

## 🐛 Solución de Problemas

### Errores Comunes

#### ❌ "OPENAI_API_KEY no está configurada"
```bash
# Solución
export OPENAI_API_KEY="tu-api-key"
# O crear archivo .env con la clave
```

#### ❌ "Semgrep no encontrado"
```bash
# Solución
pip install semgrep
# Verificar instalación
semgrep --version
```

#### ❌ "nmap no encontrado"
```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install nmap

# CentOS/RHEL/Fedora
sudo yum install nmap  # o sudo dnf install nmap

# macOS
brew install nmap

# Verificar instalación
nmap --version
```

#### ❌ "Archivo PDF no encontrado"
```bash
# Verificar que el archivo existe
ls -la tu_archivo.pdf

# Usar ruta absoluta
python main.py --pdf /ruta/completa/al/archivo.pdf

# O usar ruta relativa desde el directorio del proyecto
python main.py --pdf ./testing-assets/report.pdf
```

### Logs y Debugging

El sistema genera logs detallados en múltiples niveles:
- **Consola**: Información en tiempo real con colores
- **Archivo**: `vulnerability_validation.log` (rotación automática)
- **Nivel DEBUG**: Para troubleshooting detallado

```bash
# Ver logs en tiempo real
tail -f vulnerability_validation.log

# Ejecutar con debug verbose
python main.py --pdf report.pdf --debug

# Filtrar logs por nivel
grep "ERROR" vulnerability_validation.log
grep "WARNING" vulnerability_validation.log
```

## 🚀 Casos de Uso Reales

### 1. 🔍 Auditoría de Seguridad Automatizada
```bash
# Validar reporte completo de pentest con múltiples fuentes
python main.py \
  --pdf ./reports/pentest_Q4_2024.pdf \
  --source ./webapp/src \
  --url https://staging.empresa.com \
  --model claude-3-5-sonnet-20241022 \
  --save-output \
  --output ./audits/Q4_2024
```

### 2. 🛠️ Análisis de Código Pre-Producción
```bash
# Análisis estático antes de deploy con modelo especializado
python main.py \
  --pdf ./security_requirements.pdf \
  --source ./microservices \
  --static-only \
  --model deepseek-coder \
  --save-output
```

### 3. 🎯 Validación de Bug Bounty
```bash
# Verificar vulnerabilidades reportadas por hunters
python main.py \
  --pdf ./bug_bounty/report_001.pdf \
  --url https://app.empresa.com \
  --dynamic-only \
  --model gpt-4o \
  --save-output
```

### 4. 📊 Procesamiento Batch con Diferentes Modelos
```bash
#!/bin/bash
# Script para procesar múltiples reportes con diferentes modelos

REPORTS_DIR="./reports"
OUTPUT_DIR="./batch_results"
MODELS=("gpt-4o-mini" "claude-3-5-sonnet-20241022" "gemini-2.5-flash")

for pdf in "$REPORTS_DIR"/*.pdf; do
    filename=$(basename "$pdf" .pdf)
    for model in "${MODELS[@]}"; do
        echo "Procesando $filename con $model..."
        python main.py \
          --pdf "$pdf" \
          --extract-only \
          --model "$model" \
          --output "$OUTPUT_DIR/${filename}_${model}" \
          --save-output
    done
done
```

### 5. 🔄 Pipeline CI/CD Integration
```bash
# Integración en pipeline de CI/CD
python main.py \
  --pdf ./security_scan_results.pdf \
  --source ./src \
  --url https://pr-${PR_NUMBER}.staging.com \
  --model gpt-4o-mini \
  --save-output \
  --output ./security_reports/pr_${PR_NUMBER}

# Verificar si hay vulnerabilidades críticas
if grep -q '"severity": "Critical"' ./security_reports/pr_${PR_NUMBER}/*.json; then
    echo "❌ Vulnerabilidades críticas encontradas - Bloqueando deploy"
    exit 1
fi
```

## 📋 Mejores Prácticas

### 🎯 Selección de Modelos
- **Extracción**: Usa `gpt-4o` o `claude-3-5-sonnet` para máxima precisión
- **Análisis Estático**: `deepseek-coder` es excelente para código
- **Análisis Dinámico**: `claude-3-5-sonnet` para payloads complejos
- **Triage**: `gpt-4o-mini` es eficiente para consolidación

### 🔒 Seguridad
- Nunca hardcodees API keys en el código
- Usa archivos `.env` y `.gitignore` apropiados
- Limita el scope de análisis dinámico a entornos de testing
- Revisa los comandos generados antes de ejecución automática

### ⚡ Rendimiento
- Usa modelos más pequeños para análisis batch
- Implementa timeouts apropiados para análisis dinámico
- Considera usar caché para PDFs procesados frecuentemente
- Monitorea el uso de tokens para controlar costos

### 📊 Calidad de Resultados
- Proporciona PDFs con texto seleccionable (no imágenes escaneadas)
- Incluye contexto suficiente en los reportes PDF
- Valida URLs objetivo antes del análisis dinámico
- Revisa manualmente los resultados críticos

## 🤝 Contribución

¡Las contribuciones son bienvenidas! Por favor:

1. **Fork** el proyecto
2. **Crea** una rama para tu feature (`git checkout -b feature/nueva-funcionalidad`)
3. **Commit** tus cambios (`git commit -am 'Añadir nueva funcionalidad'`)
4. **Push** a la rama (`git push origin feature/nueva-funcionalidad`)
5. **Crea** un Pull Request

### 🎯 Áreas de Contribución Prioritarias
- 🔧 **Nuevas herramientas**: Burp Suite, OWASP ZAP, Nuclei
- 🤖 **Agentes especializados**: Web3, Mobile, Cloud Security
- 🌐 **Proveedores LLM**: Cohere, Together AI, Replicate
- 📊 **Visualización**: Dashboards, reportes HTML interactivos
- 🐳 **DevOps**: Docker, Kubernetes, CI/CD templates
- 🧪 **Testing**: Unit tests, integration tests, benchmarks

### 📝 Guías de Contribución
- Sigue PEP 8 para código Python
- Incluye docstrings en funciones públicas
- Añade tests para nuevas funcionalidades
- Actualiza la documentación correspondiente
- Usa conventional commits para mensajes

## 📝 Licencia

Este proyecto está bajo la Licencia MIT. Ver archivo [LICENSE](LICENSE) para más detalles.

## 🔗 Enlaces Útiles

### 📚 Documentación de Frameworks
- [CrewAI Documentation](https://docs.crewai.com/) - Framework de agentes multi-LLM
- [LangChain Documentation](https://python.langchain.com/) - Framework de LLM
- [Pydantic Documentation](https://docs.pydantic.dev/) - Validación de datos

### 🛠️ Herramientas de Análisis
- [Semgrep Documentation](https://semgrep.dev/docs/) - Análisis estático de código
- [Nmap Documentation](https://nmap.org/docs.html) - Network scanning
- [curl Documentation](https://curl.se/docs/) - HTTP client
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - Metodologías de testing

### 🤖 Proveedores de LLM
- [OpenAI Platform](https://platform.openai.com/docs/) - GPT models
- [Anthropic Claude](https://docs.anthropic.com/) - Claude models
- [Google AI Studio](https://ai.google.dev/) - Gemini models
- [DeepSeek Platform](https://platform.deepseek.com/) - DeepSeek models
- [Groq Console](https://console.groq.com/) - Groq models
- [Mistral Platform](https://docs.mistral.ai/) - Mistral models
- [xAI API](https://docs.x.ai/) - Grok models

### 🔒 Recursos de Seguridad
- [CWE Database](https://cwe.mitre.org/) - Common Weakness Enumeration
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Top vulnerabilities
- [CVSS Calculator](https://www.first.org/cvss/calculator/) - Vulnerability scoring
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Security standards

## 📞 Soporte y Comunidad

### 🆘 ¿Necesitas ayuda?
- 🐛 **Bugs**: Crea un [issue](../../issues) con detalles del error
- 💡 **Features**: Crea un [feature request](../../issues) con tu propuesta
- 💬 **Preguntas**: Inicia una [discusión](../../discussions) para dudas generales
- 📖 **Documentación**: Revisa este README y los comentarios en el código

### 🏷️ Plantillas de Issues
Cuando reportes un bug, incluye:
- Versión de Python y sistema operativo
- Comando ejecutado y parámetros usados
- Logs de error completos
- Archivos de ejemplo (si es posible)

### 🌟 Roadmap
- [ ] Soporte para análisis de aplicaciones móviles
- [ ] Integración con herramientas CI/CD populares
- [ ] Dashboard web para visualización de resultados
- [ ] API REST para integración externa
- [ ] Soporte para análisis de contratos inteligentes
- [ ] Plugin para IDEs populares

---

<div align="center">

**⭐ Si este proyecto te resulta útil, ¡dale una estrella! ⭐**

*Desarrollado con ❤️ para la comunidad de seguridad*

![Visitors](https://visitor-badge.laobi.icu/badge?page_id=vulnerability-validation-system)
[![GitHub stars](https://img.shields.io/github/stars/usuario/repo.svg?style=social&label=Star)](https://github.com/usuario/repo)
[![GitHub forks](https://img.shields.io/github/forks/usuario/repo.svg?style=social&label=Fork)](https://github.com/usuario/repo)

</div>