# Sistema de Validación de Vulnerabilidades con CrewAI

Sistema GenIA que utiliza un framework de agentes (CrewAI) para validar vulnerabilidades de reportes PDF mediante análisis estático y dinámico.

## 🏗️ Arquitectura

El sistema está compuesto por 4 agentes especializados:

### 1. 🔍 Agente Extractor
- **Función**: Extrae y analiza vulnerabilidades de reportes PDF
- **Herramienta**: PDFExtractorTool (PyPDF2)
- **Salida**: JSON estructurado con vulnerabilidades categorizadas
- **IA**: Asigna automáticamente títulos, CWE, categorías OWASP

### 2. 🔧 Agente Estático
- **Función**: Valida vulnerabilidades mediante análisis estático
- **Herramienta**: SemgrepTool (Semgrep)
- **Entrada**: Resultados del agente extractor + directorio de código
- **IA**: Correlaciona hallazgos con vulnerabilidades reportadas

### 3. 🎯 Agente Dinámico
- **Función**: Valida vulnerabilidades mediante análisis dinámico
- **Herramienta**: NucleiTool (Nuclei)
- **Entrada**: Resultados de extracción y análisis estático + URL objetivo
- **IA**: Crea templates de Nuclei específicos para cada vulnerabilidad

### 4. 📊 Agente de Triage
- **Función**: Consolida resultados y genera reporte final
- **Entrada**: Resultados de todos los agentes anteriores
- **IA**: Valida existencia, reclasifica severidad, genera recomendaciones

## 📁 Estructura del Proyecto

```
test3/
├── agents/                 # Agentes de CrewAI
│   ├── __init__.py
│   ├── extractor_agent.py  # Agente extractor de PDF
│   ├── static_agent.py     # Agente de análisis estático
│   ├── dynamic_agent.py    # Agente de análisis dinámico
│   └── triage_agent.py     # Agente de triage
├── tools/                  # Herramientas especializadas
│   ├── __init__.py
│   ├── pdf_tool.py         # Extracción de PDF
│   ├── semgrep_tool.py     # Análisis estático
│   └── nuclei_tool.py      # Análisis dinámico
├── tasks/                  # Definiciones de tareas
│   ├── __init__.py
│   ├── extraction_task.py  # Tarea de extracción
│   ├── static_analysis_task.py  # Tarea de análisis estático
│   ├── dynamic_analysis_task.py # Tarea de análisis dinámico
│   └── triage_task.py      # Tarea de triage
├── main.py                 # Punto de entrada principal
├── requirements.txt        # Dependencias
└── README.md              # Este archivo
```

## 🚀 Instalación

### Prerrequisitos

1. **Python 3.8+**
2. **OpenAI API Key**
3. **Semgrep** (para análisis estático)
4. **Nuclei** (para análisis dinámico)

### Instalación de Dependencias

```bash
# Clonar o descargar el proyecto
cd test3

# Instalar dependencias de Python
pip install -r requirements.txt

# Instalar Semgrep
pip install semgrep
# O usando el instalador oficial:
curl -sSL https://semgrep.dev/install | sh

# Instalar Nuclei
# En Windows (usando Go):
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# O descargar desde releases:
# https://github.com/projectdiscovery/nuclei/releases
```

### Configuración

1. **Configurar OpenAI API Key**:
```bash
# Windows PowerShell
$env:OPENAI_API_KEY="tu-api-key-aqui"

# Windows CMD
set OPENAI_API_KEY=tu-api-key-aqui

# Linux/Mac
export OPENAI_API_KEY="tu-api-key-aqui"
```

2. **Preparar archivos de entrada**:
   - Coloca tu reporte PDF como `sample_report.pdf`
   - Crea directorio `source_code/` con el código a analizar
   - Configura la URL objetivo en `main.py`

## 📖 Uso

### Ejecución con Argumentos (Recomendado)

```bash
# Uso básico
python main.py --pdf reporte.pdf --source ./codigo --url https://ejemplo.com

# Con argumentos cortos
python main.py -p vuln_report.pdf -s /ruta/al/codigo -u http://localhost:8080

# Especificando directorio de salida
python main.py --pdf report.pdf --source ./src --url https://app.com --output ./mis_resultados

# Con API key como argumento
python main.py --pdf report.pdf --source ./src --url https://app.com --api-key tu-openai-key
```

### Argumentos Disponibles

- `-p, --pdf` (requerido): Ruta al archivo PDF del reporte
- `-s, --source` (requerido): Directorio del código fuente
- `-u, --url` (requerido): URL objetivo para pruebas dinámicas
- `-o, --output` (opcional): Directorio de salida (default: ./results)
- `--api-key` (opcional): OpenAI API Key

### Ver Ayuda

```bash
python main.py --help
```

### Flujo de Ejecución

1. **Extracción**: Analiza el PDF y extrae vulnerabilidades
2. **Análisis Estático**: Valida con Semgrep en el código fuente
3. **Análisis Dinámico**: Prueba con Nuclei en la URL objetivo
4. **Triage**: Consolida resultados y genera reporte final

## 📊 Resultados

El sistema genera varios archivos de salida en el directorio `results/`:

- `validation_result_YYYYMMDD_HHMMSS.json` - Resultado consolidado
- `extraction_YYYYMMDD_HHMMSS.json` - Vulnerabilidades extraídas
- `static_analysis_YYYYMMDD_HHMMSS.json` - Resultados de Semgrep
- `dynamic_analysis_YYYYMMDD_HHMMSS.json` - Resultados de Nuclei
- `final_report_YYYYMMDD_HHMMSS.json` - Reporte final de triage

### Estructura de Salida

```json
{
  "extraction_results": "...",
  "static_analysis_results": "...",
  "dynamic_analysis_results": "...",
  "final_triage_report": "...",
  "metadata": {
    "pdf_path": "./sample_report.pdf",
    "source_code_path": "./source_code",
    "target_url": "http://localhost:8080",
    "analysis_date": "2024-01-15T10:30:00",
    "system_version": "1.0.0"
  }
}
```

## 🔧 Personalización

### Modificar Agentes

Cada agente puede ser personalizado editando su archivo correspondiente en `agents/`:

- **Rol y objetivo**: Modifica `role` y `goal`
- **Backstory**: Ajusta el contexto del agente
- **Herramientas**: Añade o quita herramientas

### Añadir Nuevas Herramientas

1. Crea una nueva clase en `tools/`
2. Hereda de `BaseTool` de CrewAI
3. Implementa el método `_run()`
4. Añade la herramienta al agente correspondiente

### Modificar Tareas

Las tareas se definen en `tasks/` y pueden ser personalizadas:

- **Descripción**: Instrucciones detalladas para el agente
- **Salida esperada**: Formato y contenido de la respuesta
- **Contexto**: Dependencias de otras tareas

## 🐛 Solución de Problemas

### Errores Comunes

1. **"OPENAI_API_KEY no está configurada"**
   - Verifica que la variable de entorno esté configurada
   - Reinicia la terminal después de configurarla

2. **"Archivo PDF no encontrado"**
   - Verifica que el archivo existe en la ruta especificada
   - Usa rutas absolutas si hay problemas con rutas relativas

3. **"Semgrep no encontrado"**
   - Instala Semgrep: `pip install semgrep`
   - Verifica que esté en el PATH: `semgrep --version`

4. **"Nuclei no encontrado"**
   - Instala Nuclei desde releases de GitHub
   - Añade al PATH del sistema
   - Verifica: `nuclei -version`

### Logs

El sistema genera logs en:
- Consola (tiempo real)
- Archivo `vulnerability_validation.log`

## 🤝 Contribución

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -am 'Añadir nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crea un Pull Request

## 📝 Licencia

Este proyecto está bajo la Licencia MIT. Ver archivo `LICENSE` para más detalles.

## 🔗 Enlaces Útiles

- [CrewAI Documentation](https://docs.crewai.com/)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Nuclei Documentation](https://nuclei.projectdiscovery.io/)
- [OpenAI API Documentation](https://platform.openai.com/docs/)

## 📞 Soporte

Para reportar bugs o solicitar features, por favor crea un issue en el repositorio del proyecto.