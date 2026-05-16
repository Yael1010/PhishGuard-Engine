# 🛡️ PhishGuard - Sistema de Detección de Phishing

> Motor heurístico de código abierto para la detección de correos electrónicos de phishing mediante análisis de múltiples factores.

![Python](https://img.shields.io/badge/Python-3.9+-blue?style=flat&logo=python)
![Next.js](https://img.shields.io/badge/Next.js-16-black?style=flat&logo=next.js)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-009790?style=flat&logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-green)

## Descripción

PhishGuard es un sistema de detección de phishing que analiza correos electrónicos utilizando un motor heurístico basado en reglas. El sistema evalúa múltiples factores como cabeceras de correo, enlaces, contenido semántico y archivos adjuntos para determinar si un correo es legítimo, sospechoso o malicioso.

## Características

### Backend (FastAPI)
- **Motor Heurístico**: Sistema basado en reglas con 10+ indicadores de riesgo
- **Análisis OSINT**: Consulta la edad de dominios mediante WHOIS
- **Extracción de datos**: Procesa archivos CSV y EML
- **Integración con Supabase**: Almacena historial en la nube
- **Generación de PDFs**: Reportes descargables de cada análisis

### Frontend (Next.js)
- **Dashboard interactivo**: Visualización de estadísticas en tiempo real
- **Gráfico de barras**: Análisis de los últimos 7 días
- **Mapa de calor**: Frecuencia de activación de reglas
- **Análisis manual**: Evaluación de correos específicos
- **Historial**: Registro completo con filtros y búsqueda
- **Modo oscuro/claro**: Interfaz adaptativa

## 🏗️ Estructura del Proyecto

```
phishguard_project/
├── api/                    # Backend FastAPI
│   ├── main.py             # API principal
│   ├── src/                # Módulos del sistema
│   │   ├── engine.py       # Motor de inferencia
│   │   ├── memory.py      # Memoria de trabajo
│   │   ├── extractor.py   # Extracción de datos
│   │   ├── database.py    # Integración Supabase
│   │   └── osint.py       # Análisis WHOIS
│   ├── requirements.txt
│   └── .env.example       # Variables de entorno
│
├── frontend/               # Frontend Next.js
│   ├── src/
│   │   ├── app/           # Páginas de la app
│   │   ├── components/    # Componentes React
│   │   ├── services/      # Cliente API
│   │   └── types/         # Tipos TypeScript
│   └── package.json
│
├── config/                 # Configuración
│   └── knowledge_base.json
│
└── data/                   # Datos de prueba
```

## Instalación

### Prerrequisitos

- Python 3.9 o superior
- Node.js 18 o superior
- Cuenta de Supabase (gratis)

### Paso 1: Clonar el repositorio

```bash
git clone https://github.com/tu-usuario/phishguard.git
cd phishguard
```

### Paso 2: Configurar el Backend

```bash
cd api

# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# Windows: venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.example .env
# Edita .env con tus credenciales de Supabase
```

### Paso 3: Configurar el Frontend

```bash
cd frontend

# Instalar dependencias
npm install

# Configurar URL de la API
# Crea un archivo .env.local con:
# NEXT_PUBLIC_API_URL=http://localhost:8000

# Iniciar desarrollo
npm run dev
```

## Uso

### Iniciar el Backend

```bash
cd api
python main.py
```

La API estará disponible en: `http://localhost:8000`

### Iniciar el Frontend

```bash
cd frontend
npm run dev
```

La aplicación estará disponible en: `http://localhost:3000`

## 📡 Endpoints de la API

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/api/health` | Estado del servidor |
| GET | `/api/reglas` | Lista de reglas heurísticas |
| GET | `/api/estadisticas` | Estadísticas generales |
| GET | `/api/historial` | Historial de análisis |
| GET | `/api/analisis/dias` | Análisis por días |
| GET | `/api/heatmap/reglas` | Mapa de calor de reglas |
| POST | `/api/v1/analizar` | Analizar correo |
| POST | `/api/analizar/csv` | Analizar archivo CSV |
| POST | `/api/analizar/eml` | Analizar archivo EML |
| POST | `/api/analizar/manual` | Análisis manual |
| GET | `/api/reporte/{id}` | Descargar reporte PDF |

## 📊 Reglas Heurísticas

| ID | Categoría | Descripción | Peso |
|----|-----------|-------------|------|
| H1 | Metadatos | Inconsistencia de dominio (From vs Return-Path) | +40 |
| H2 | Metadatos | Fallo en autenticación SPF o DKIM | +30 |
| U1 | Enlaces | URL con dirección IP | +45 |
| U2 | Enlaces | Discrepancia enlace visible vs real | +35 |
| U3 | Enlaces | Uso de acortadores sospechosos | +20 |
| S1 | Semántica | Lenguaje de urgencia/amenaza | +25 |
| S2 | Semántica | Saludos genéricos | +15 |
| A1 | Adjuntos | Extensión peligrosa (.exe, .bat) | +50 |
| A2 | Adjuntos | Archivo comprimido (.zip, .rar) | +30 |


## 🤝 Contribuir

Las contribuciones son bienvenidas. Por favor, lee las pautas de contribución antes de enviar un PR.

1. Fork el proyecto
2. Crea tu rama de características (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request


## ⚠️ Disclaimer

Este software es una herramienta de apoyo para la detección de phishing. No garantiza una protección del 100% contra todos los ataques de phishing. Se recomienda usar este sistema como parte de una estrategia de seguridad más amplia.

---
