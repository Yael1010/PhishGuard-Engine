# PhishGuard - Sistema de Detección de Phishing

## Estructura del Proyecto

```
phishguard_project/
├── api/                 # Backend FastAPI
│   ├── main.py         # API principal
│   ├── src/            # Módulos del motor heurístico
│   ├── requirements.txt
│   └── .env            # Variables de entorno
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
- Cuenta de Supabase (ya configurada)

## Instalación

### Backend (API)

```bash
cd api
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
SUPABASE_URL=https://zytpihaxzyuvucgkwrsp.supabase.co
SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Frontend (frontend/.env.local)
```
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## Despliegue en Vercel

### Opción 1: Backend y Frontend separados

**Backend (FastAPI):**
1. Crear un proyecto en Vercel
2. Conectar el repositorio
3. Configurar:
   - Build Command: `pip install -r requirements.txt`
   - Output Directory: `api`
   - Install Command: `pip install -r requirements.txt`

**Frontend (Next.js):**
1. Crear otro proyecto en Vercel
2. Conectar la carpeta `frontend`
3. En Settings > Environment Variables agregar:
   - `NEXT_PUBLIC_API_URL` = URL del backend desplegado

### Opción 2: Usar API Routes de Next.js

Si prefieres un solo proyecto, puedes mover la lógica de FastAPI a Next.js API Routes.

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
- Gráfico de barras (últimos 7 días)
- Mapa de calor de reglas
- Estadísticas en tiempo real
- Análisis manual de correos
- Carga de archivos CSV y .eml
- Descarga de reportes PDF
- Historial con filtros
- Toast notifications
- Skeleton loaders
- Tooltips en reglas heurísticas
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