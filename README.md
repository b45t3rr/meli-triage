# 🛡️ Sistema de Validación de Vulnerabilidades con IA

> **Sistema inteligente de análisis de vulnerabilidades que combina extracción de PDF, análisis estático y dinámico usando agentes de IA especializados**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![CrewAI](https://img.shields.io/badge/CrewAI-Latest-green.svg)](https://crewai.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🎯 ¿Qué hace este sistema?

Este sistema automatiza la validación de vulnerabilidades de seguridad mediante un enfoque de **múltiples agentes de IA** que trabajan en conjunto:

1. **📄 Extrae** vulnerabilidades de reportes PDF
2. **🔍 Analiza** código fuente estáticamente con Semgrep
3. **🎯 Prueba** aplicaciones dinámicamente con Nuclei
4. **📊 Consolida** resultados en un reporte final inteligente

## ✨ Características Principales

### 🤖 Soporte Multi-LLM
Compatible con los mejores modelos de IA del mercado:
- **OpenAI**: GPT-5, GPT-4o, GPT-4o-mini, O1, GPT-4
- **Anthropic**: Claude 3.5 Sonnet, Claude 3.7 Sonnet
- **Google**: Gemini 2.5 Flash, Gemini 1.5 Pro
- **DeepSeek**: DeepSeek Chat, DeepSeek Coder
- **Groq**: Llama 3.3, Mixtral, Gemma2
- **Mistral**: Mistral Large/Medium/Small
- **xAI**: grok-4, grok-3, grok-3-mini

### 🏗️ Arquitectura de 4 Agentes Especializados

| Agente | Función | Herramienta | Especialidad |
|--------|---------|-------------|-------------|
| 🔍 **Extractor** | Analiza PDFs | PyPDF2 | Categorización automática con CWE/OWASP |
| 🔧 **Estático** | Análisis de código | Semgrep | Correlación de vulnerabilidades en código |
| 🎯 **Dinámico** | Pruebas en vivo | Nuclei | Templates personalizados por vulnerabilidad |
| 📊 **Triage** | Consolidación | IA | Validación y reclasificación inteligente |

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

# Instalar herramientas de análisis
pip install semgrep
```

### 2. Instalar Nuclei
```bash
# Opción 1: Usando Go
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Opción 2: Descargar binario
# Visita: https://github.com/projectdiscovery/nuclei/releases
```

### 3. Configurar API Keys
```bash
# Crear archivo .env
echo "OPENAI_API_KEY=tu-api-key-aqui" > .env

# O exportar como variable de entorno
export OPENAI_API_KEY="tu-api-key-aqui"
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
# GPT 5 mini
python main.py --model gpt-5-mini --pdf report.pdf --extract-only

# Grok 3 Mini
python main.py --model grok-3-mini --pdf report.pdf --source ./src --url https://app.com

# DeepSeek chat
python main.py --model deepseek-chat --pdf report.pdf --static-only --source ./code
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

El sistema genera archivos estructurados en el directorio `results/`:

```
results/
├── validation_result_20240115_103000.json    # Resultado consolidado
├── extraction_20240115_103000.json           # Vulnerabilidades extraídas
├── static_analysis_20240115_103000.json      # Resultados Semgrep
├── dynamic_analysis_20240115_103000.json     # Resultados Nuclei
└── final_report_20240115_103000.json         # Reporte final de triage
```

### Estructura de Salida JSON
```json
{
  "extraction_results": {
    "vulnerabilities": [
      {
        "title": "SQL Injection en login",
        "cwe": "CWE-89",
        "owasp_category": "A03:2021 – Injection",
        "severity": "High",
        "description": "...",
        "location": "login.php línea 45"
      }
    ]
  },
  "static_analysis_results": [...],
  "dynamic_analysis_results": [...],
  "final_triage_report": {
    "validated_vulnerabilities": [...],
    "false_positives": [...],
    "recommendations": [...]
  },
  "metadata": {
    "analysis_date": "2024-01-15T10:30:00",
    "model_used": "gpt-4o-mini",
    "execution_time": "45.2s"
  }
}
```

## 🏗️ Estructura del Proyecto

```
test3/
├── 🤖 agents/                 # Agentes de IA especializados
│   ├── extractor_agent.py     # Extracción y categorización de PDF
│   ├── static_agent.py        # Análisis estático con Semgrep
│   ├── dynamic_agent.py       # Análisis dinámico con Nuclei
│   └── triage_agent.py        # Consolidación y triage inteligente
├── 🛠️ tools/                  # Herramientas especializadas
│   ├── pdf_tool.py            # Extracción de texto de PDF
│   ├── semgrep_tool.py        # Interfaz con Semgrep
│   └── nuclei_tool.py         # Interfaz con Nuclei
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

## 🔧 Configuración Avanzada

### Variables de Entorno
```bash
# APIs de LLM
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_API_KEY=AI...
DEEPSEEK_API_KEY=sk-...
GROQ_API_KEY=gsk_...
MISTRAL_API_KEY=...

# MongoDB (opcional)
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=vulnerability_db

# Configuraciones adicionales
LOG_LEVEL=INFO
OUTPUT_FORMAT=json
```

### Personalización de Agentes

Cada agente puede ser personalizado editando su archivo correspondiente:

```python
# agents/extractor_agent.py
self.agent = Agent(
    role="Tu rol personalizado",
    goal="Tu objetivo específico",
    backstory="Contexto personalizado del agente",
    tools=[self.pdf_tool],
    llm=self.llm
)
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

#### ❌ "Nuclei no encontrado"
```bash
# Solución
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
# Verificar instalación
nuclei -version
```

#### ❌ "Archivo PDF no encontrado"
```bash
# Usar ruta absoluta
python main.py --pdf /ruta/completa/al/archivo.pdf
```

### Logs y Debugging

El sistema genera logs detallados:
- **Consola**: Información en tiempo real
- **Archivo**: `vulnerability_validation.log`

```bash
# Ver logs en tiempo real
tail -f vulnerability_validation.log
```

## 🚀 Casos de Uso

### 1. Auditoría de Seguridad Automatizada
```bash
# Validar reporte de pentest
python main.py --pdf pentest_report.pdf --source ./webapp --url https://app.empresa.com
```

### 2. Análisis de Código Pre-Producción
```bash
# Solo análisis estático antes de deploy
python main.py --pdf security_requirements.pdf --source ./src --static-only
```

### 3. Validación de Vulnerabilidades Reportadas
```bash
# Verificar si vulnerabilidades siguen existiendo
python main.py --pdf bug_bounty_report.pdf --url https://staging.app.com --dynamic-only
```

### 4. Procesamiento Batch de Reportes
```bash
# Procesar múltiples reportes
for pdf in reports/*.pdf; do
    python main.py --pdf "$pdf" --extract-only --output "./results/$(basename "$pdf" .pdf)"
done
```

## 🤝 Contribución

¡Las contribuciones son bienvenidas! Por favor:

1. **Fork** el proyecto
2. **Crea** una rama para tu feature (`git checkout -b feature/nueva-funcionalidad`)
3. **Commit** tus cambios (`git commit -am 'Añadir nueva funcionalidad'`)
4. **Push** a la rama (`git push origin feature/nueva-funcionalidad`)
5. **Crea** un Pull Request

### Áreas de Contribución
- 🔧 Nuevas herramientas de análisis
- 🤖 Agentes especializados adicionales
- 🌐 Soporte para más proveedores LLM
- 📊 Mejoras en reportes y visualización
- 🐳 Containerización y deployment

## 📝 Licencia

Este proyecto está bajo la Licencia MIT. Ver archivo [LICENSE](LICENSE) para más detalles.

## 🔗 Enlaces Útiles

- 📚 [Documentación CrewAI](https://docs.crewai.com/)
- 🔍 [Documentación Semgrep](https://semgrep.dev/docs/)
- 🎯 [Documentación Nuclei](https://nuclei.projectdiscovery.io/)
- 🤖 [OpenAI API](https://platform.openai.com/docs/)
- 🧠 [Anthropic Claude](https://docs.anthropic.com/)
- 🌟 [Google Gemini](https://ai.google.dev/)

## 📞 Soporte

¿Necesitas ayuda? 

- 🐛 **Bugs**: Crea un [issue](../../issues)
- 💡 **Features**: Crea un [feature request](../../issues)
- 💬 **Preguntas**: Inicia una [discusión](../../discussions)

---

<div align="center">

**⭐ Si este proyecto te resulta útil, ¡dale una estrella! ⭐**

*Desarrollado con ❤️ para la comunidad de seguridad*

</div>