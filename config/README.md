# Configuration Module

Este módulo contiene todas las configuraciones del sistema de validación de vulnerabilidades.

## Contenido

### Configuraciones

- **llm_config.py**: Configuración de modelos LLM (Large Language Models)
  - Configuración de proveedores (OpenAI, Anthropic, Mistral, etc.)
  - Gestión de API keys
  - Parámetros de modelos
  - Funciones de utilidad para crear instancias de LLM

## Uso

Para usar las configuraciones desde otros módulos:

```python
from config.llm_config import create_llm_instance, get_model_info

# Crear una instancia de LLM
llm = create_llm_instance()

# Obtener información del modelo
info = get_model_info()
```

## Variables de Entorno

Asegúrate de configurar las siguientes variables de entorno:

- `OPENAI_API_KEY`: API key de OpenAI
- `ANTHROPIC_API_KEY`: API key de Anthropic
- `MISTRAL_API_KEY`: API key de Mistral
- `GROQ_API_KEY`: API key de Groq

## Estructura

Este módulo sigue el patrón de configuración centralizada, permitiendo un manejo consistente de todas las configuraciones del sistema.