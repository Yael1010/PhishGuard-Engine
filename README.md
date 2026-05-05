# PhishGuard - Sistema de Detección de Phishing

## Estructura del Proyecto

```
phishguard_project/
├── api/                 # Backend FastAPI
│   ├── main.py         # API principal
│   ├── src/            # Módulos del motor heurístico
│   ├── requirements.txt
│   └── .env.example    # Ejemplo de variables de entorno
│
├── frontend/           # Frontend Next.js
│   ├── src/
│   │   ├── app/        # Páginas Next.js
│   │   ├── components/ # Componentes React
│   │   ├── services/   # API client
│   │   └── types/      # TypeScript types
│   ├── .env.local      # URL de la API
│   └── package.json
│
├── config/             # Configuración
│   └── knowledge_base.json
│
└── data/               # Datos de prueba
```

## Requisitos

- Python 3.9+
- Node.js 18+
- Cuenta de Supabase

## Instalación

### Backend (API)

```bash
cd api
cp .env.example .env
# Edita .env con tus credenciales de Supabase
pip install -r requirements.txt
python main.py
```

La API estará disponible en `http://localhost:8000`

### Frontend (Next.js)

```bash
cd frontend
npm install
npm run dev
```

El frontend estará disponible en `http://localhost:3000`

## Configuración de Variables de Entorno

### Backend (api/.env)
```
SUPABASE_URL=tu_url_de_supabase
SUPABASE_KEY=tu_key_de_supabase
```

### Frontend (frontend/.env.local)
```
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## Despliegue en Vercel

### Preparación del repositorio

1. Sube este proyecto a GitHub
2. Crea dos proyectos en Vercel (uno para backend, uno para frontend)

### Backend (FastAPI)

1. Importa el repositorio en Vercel
2. Configura:
   - Framework Preset: Other
   - Build Command: `pip install -r requirements.txt`
   - Output Directory: `api`
   - Install Command: `pip install -r requirements.txt`
3. En Environment Variables agrega:
   - `SUPABASE_URL` - Tu URL de Supabase
   - `SUPABASE_KEY` - Tu key de Supabase

### Frontend (Next.js)

1. Importa el repositorio en Vercel
2. Configura:
   - Framework Preset: Next.js
3. En Environment Variables agrega:
   - `NEXT_PUBLIC_API_URL` - URL del backend desplegado (ej: https://tu-api.vercel.app)

### Opción alternativa: un solo proyecto

Si prefieres un solo proyecto, puedes usar API Routes de Next.js para el backend.

## Endpoints de la API

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/api/health` | Verificar estado |
| GET | `/api/reglas` | Obtener reglas heurísticas |
| GET | `/api/estadisticas` | Estadísticas generales |
| GET | `/api/historial` | Historial de análisis |
| GET | `/api/analisis/dias?dias=7` | Análisis por días |
| GET | `/api/heatmap/reglas` | Mapa de calor |
| POST | `/api/v1/analizar` | Analizar correo |
| POST | `/api/analizar/csv` | Analizar CSV |
| POST | `/api/analizar/eml` | Analizar archivo .eml |
| POST | `/api/analizar/manual` | Análisis manual |
| GET | `/api/reporte/{id}` | Descargar PDF |

## Funcionalidades Implementadas

### Frontend
- Dashboard con sidebar de navegación
- Gráfico de barras (últimos 7 días)
- Mapa de calor de reglas
- Estadísticas en tiempo real
- Análisis manual de correos
- Carga de archivos CSV y .eml
- Descarga de reportes PDF
- Historial con filtros
- Toast notifications
- Modo oscuro/claro

### Backend
- Motor heurístico de detección
- Integración con Supabase
- Extracción de datos de .eml y CSV
- Análisis OSINT (edad de dominio)
- Generación de reportes PDF

## Uso Local

1. Iniciar el backend:
   ```bash
   cd api && python main.py
   ```

2. Iniciar el frontend:
   ```bash
   cd frontend && npm run dev
   ```

3. Abrir `http://localhost:3000` en el navegador