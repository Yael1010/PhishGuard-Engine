import os
import sys
import io
import pandas as pd
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
import uvicorn

# Configuración de rutas
directorio_base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(directorio_base, 'src'))

from memory import MemoriaDeTrabajo
from engine import MotorInferencia
from extractor import ExtractorMasivo
from database import SupabaseManager

# Inicializamos FastAPI (Esto genera documentación automática)
app = FastAPI(title="PhishGuard Engine API", version="1.4", description="Motor heurístico para detección de phishing")

# Le indicamos a FastAPI dónde están los archivos HTML
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# Inicializamos los módulos del sistema
ruta_kb = os.path.join(directorio_base, 'config', 'knowledge_base.json')
motor = MotorInferencia(ruta_kb=ruta_kb)
extractor = ExtractorMasivo()
db = SupabaseManager()

@app.get("/")
async def index_get(request: Request):
    """Ruta para cargar el Dashboard la primera vez (GET)"""
    estadisticas_reales = db.obtener_resumen_estadistico()
    historial_db = db.obtener_historial_completo()
    
    # En FastAPI moderno, declaramos explícitamente request, name y context
    return templates.TemplateResponse(
        request=request,
        name="index.html", 
        context={
            "request": request, 
            "resultados_manual": None,
            "resultados_masivos": None,
            "estadisticas": estadisticas_reales,
            "historial_db": historial_db,
            "hechos": None
        }
    )

@app.post("/")
async def index_post(request: Request):
    """Ruta para procesar los envíos de formularios y archivos (POST)"""
    form = await request.form()
    
    resultados_manual = None
    resultados_masivos = None
    hechos_extraidos = None

    # --- CASO 1: Análisis Automatizado (CSV) ---
    archivo_csv = form.get("archivo_csv")
    if archivo_csv and archivo_csv.filename:
        try:
            contenido = await archivo_csv.read()
            # Convertimos los bytes asíncronos para que Pandas los lea
            df_correos = pd.read_csv(io.BytesIO(contenido))
            resultados_masivos = []
            
            for _, fila in df_correos.iterrows():
                hechos = extractor.extraer_hechos_de_fila(fila)
                memoria = MemoriaDeTrabajo()
                memoria.cargar_hechos(hechos)
                motor.ejecutar_forward_chaining(memoria)
                
                db.guardar_registro(
                    remitente=hechos['dominio_remitente'],
                    score=memoria.puntaje_riesgo,
                    clasificacion=memoria.clasificacion_final,
                    tipo_amenaza=memoria.tipo_amenaza,
                    reglas=[log['regla'] for log in memoria.reglas_activadas]
                )
                
                resultados_masivos.append({
                    'id': fila.get('id', 'N/A'),
                    'remitente': hechos['dominio_remitente'],
                    'clasificacion': memoria.clasificacion_final,
                    'tipo_amenaza': memoria.tipo_amenaza,
                    'score': memoria.puntaje_riesgo,
                    'reglas': [log['regla'] for log in memoria.reglas_activadas]
                })
        except Exception as e:
            print(f"Error procesando CSV: {e}")

    # --- CASO 2: Escáner Individual (.EML) ---
    elif form.get("archivo_eml") and form.get("archivo_eml").filename:
        archivo_eml = form.get("archivo_eml")
        # Compatibilidad: FastAPI usa .file en lugar de .stream (Flask)
        archivo_eml.stream = archivo_eml.file 
        hechos = extractor.extraer_hechos_de_eml(archivo_eml)
        
        if hechos:
            hechos_extraidos = hechos
            memoria = MemoriaDeTrabajo()
            memoria.cargar_hechos(hechos)
            motor.ejecutar_forward_chaining(memoria)

            db.guardar_registro(
                remitente=hechos['dominio_remitente'],
                score=memoria.puntaje_riesgo,
                clasificacion=memoria.clasificacion_final,
                tipo_amenaza=memoria.tipo_amenaza,
                reglas=[log['regla'] for log in memoria.reglas_activadas]
            )

            resultados_manual = memoria.obtener_estado_actual()
            resultados_manual['clasificacion'] = memoria.clasificacion_final
            resultados_manual['tipo_amenaza'] = memoria.tipo_amenaza

    # --- CASO 3: Simulación Manual ---
    elif form.get("dominio_remitente"):
        correo_simulado = {
            "dominio_remitente": str(form.get('dominio_remitente', '')).lower(),
            "dominio_ruta_retorno": str(form.get('dominio_ruta_retorno', '')).lower(),
            "estado_SPF": str(form.get('estado_SPF', 'Aprobado')),
            "estado_DKIM": str(form.get('estado_DKIM', 'Aprobado')),
            "lista_enlaces_URL": [str(form.get('destino_enlace', ''))],
            "texto_visible_enlace": str(form.get('texto_enlace', '')),
            "destino_real_enlace": str(form.get('destino_enlace', '')),
            "cuerpo_mensaje": str(form.get('cuerpo_mensaje', '')),
            "extension_adjunto": str(form.get('extension_adjunto', ''))
        }

        hechos_extraidos = correo_simulado
        memoria = MemoriaDeTrabajo()
        memoria.cargar_hechos(correo_simulado)
        motor.ejecutar_forward_chaining(memoria)

        db.guardar_registro(
            remitente=correo_simulado['dominio_remitente'],
            score=memoria.puntaje_riesgo,
            clasificacion=memoria.clasificacion_final,
            tipo_amenaza=memoria.tipo_amenaza,
            reglas=[log['regla'] for log in memoria.reglas_activadas]
        )

        resultados_manual = memoria.obtener_estado_actual()
        resultados_manual['clasificacion'] = memoria.clasificacion_final
        resultados_manual['tipo_amenaza'] = memoria.tipo_amenaza

    # --- DATOS PERSISTENTES ---
    estadisticas_reales = db.obtener_resumen_estadistico()
    historial_db = db.obtener_historial_completo()

    return templates.TemplateResponse(
        request=request,
        name="index.html", 
        context={
            "request": request, 
            "resultados_manual": resultados_manual, 
            "resultados_masivos": resultados_masivos,
            "estadisticas": estadisticas_reales,
            "historial_db": historial_db,
            "hechos": hechos_extraidos
        }
    )

if __name__ == '__main__':
    # Uvicorn reemplaza al servidor de pruebas de Flask
    print("Iniciando PhishGuard FastAPI en http://127.0.0.1:8000")
    uvicorn.run("dashboard:app", host="127.0.0.1", port=8000, reload=True)