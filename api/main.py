import os
import sys
import io
import json
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Request, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
import pandas as pd
from pydantic import BaseModel

# Rutas
directorio_base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(directorio_base, 'api', 'src'))

from src.memory import MemoriaDeTrabajo
from src.engine import MotorInferencia
from src.extractor import ExtractorMasivo
from src.database import SupabaseManager
from src.osint import AnalizadorOSINT
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch

app = FastAPI(title="PhishGuard API", version="2.0", description="API para detección de phishing")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inicializar módulos
ruta_kb = os.path.join(directorio_base, 'config', 'knowledge_base.json')
motor = MotorInferencia(ruta_kb=ruta_kb)
extractor = ExtractorMasivo()
db = SupabaseManager()
analizador_osint = AnalizadorOSINT()

# Cargar conocimiento de reglas para tooltips
with open(ruta_kb, 'r', encoding='utf-8') as f:
    kb_data = json.load(f)
    reglas_info = {r['id_regla']: r for r in kb_data['reglas']}

class CorreoRequest(BaseModel):
    dominio_remitente: str
    dominio_ruta_retorno: str
    estado_SPF: str = "Aprobado"
    estado_DKIM: str = "Aprobado"
    enlaces: list = []
    texto_enlace: str = ""
    cuerpo_mensaje: str = ""
    extension_adjunto: str = ""

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "version": "2.0"}

@app.get("/api/reglas")
async def obtener_reglas():
    return {"reglas": kb_data["reglas"], "umbrales": kb_data["umbrales_decision"]}

@app.get("/api/estadisticas")
async def obtener_estadisticas():
    stats = db.obtener_resumen_estadistico()
    return stats

@app.get("/api/historial")
async def obtener_historial(limit: int = 100):
    historial = db.obtener_historial_completo()
    return historial[:limit]

@app.get("/api/analisis/dias")
async def analisis_por_dias(dias: int = 7):
    historial = db.obtener_historial_completo()

    fecha_limite = datetime.now() - timedelta(days=dias)
    dias_data = {}

    for i in range(dias):
        fecha = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
        dias_data[fecha] = {"Legítimo": 0, "Sospechoso": 0, "Malicioso": 0}

    for reg in historial:
        try:
            fecha = reg.get('created_at', '')[:10]
            if fecha in dias_data:
                clasif = reg.get('clasificacion', 'Legítimo')
                if clasif in dias_data[fecha]:
                    dias_data[fecha][clasif] += 1
        except:
            pass

    return {"dias": list(reversed(list(dias_data.keys()))), "data": list(reversed(list(dias_data.values())))}

@app.get("/api/heatmap/reglas")
async def heatmap_reglas():
    historial = db.obtener_historial_completo()

    heatmap = {}
    for clasif in ["Legítimo", "Sospechoso", "Malicioso"]:
        heatmap[clasif] = {}
        for regla in ["H1", "H2", "U1", "U2", "U3", "S1", "S2", "A1", "A2"]:
            heatmap[clasif][regla] = 0

    for reg in historial:
        clasif = reg.get('clasificacion', 'Legítimo')
        reglas_str = reg.get('reglas_activadas', '')
        if reglas_str:
            reglas = reglas_str.split(',')
            for regla in reglas:
                regla = regla.strip()
                if regla in heatmap.get(clasif, {}):
                    heatmap[clasif][regla] += 1

    return heatmap

@app.post("/api/v1/analizar")
async def api_analizar_correo(datos: CorreoRequest):
    edad_dias = analizador_osint.obtener_edad_dominio(datos.dominio_remitente)

    hechos = {
        "dominio_remitente": datos.dominio_remitente.lower(),
        "dominio_ruta_retorno": datos.dominio_ruta_retorno.lower(),
        "estado_SPF": datos.estado_SPF,
        "estado_DKIM": datos.estado_DKIM,
        "lista_enlaces_URL": datos.enlaces,
        "texto_visible_enlace": datos.texto_enlace,
        "destino_real_enlace": datos.enlaces[0] if datos.enlaces else "",
        "cuerpo_mensaje": datos.cuerpo_mensaje,
        "extension_adjunto": datos.extension_adjunto.lower(),
        "edad_dominio_dias": edad_dias
    }

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

    return {
        "status": "success",
        "resultados_heuristica": memoria.obtener_estado_actual(),
        "clasificacion": memoria.clasificacion_final,
        "tipo_amenaza": memoria.tipo_amenaza,
        "hechos": hechos
    }

@app.post("/api/analizar/csv")
async def analizar_csv(file: UploadFile = File(...)):
    try:
        contenido = await file.read()
        df_correos = pd.read_csv(io.BytesIO(contenido))
        resultados = []

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

            resultados.append({
                'id': fila.get('id', 'N/A'),
                'remitente': hechos['dominio_remitente'],
                'clasificacion': memoria.clasificacion_final,
                'tipo_amenaza': memoria.tipo_amenaza,
                'score': memoria.puntaje_riesgo,
                'reglas': [log['regla'] for log in memoria.reglas_activadas]
            })

        return {"status": "success", "resultados": resultados, "total": len(resultados)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/analizar/eml")
async def analizar_eml(file: UploadFile = File(...)):
    try:
        archivo_eml = file
        archivo_eml.stream = archivo_eml.file

        hechos = extractor.extraer_hechos_de_eml(archivo_eml)

        if not hechos:
            return {"status": "error", "message": "No se pudo procesar el archivo .eml"}

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

        return {
            "status": "success",
            "hechos": hechos,
            "resultados": memoria.obtener_estado_actual(),
            "clasificacion": memoria.clasificacion_final,
            "tipo_amenaza": memoria.tipo_amenaza
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/analizar/manual")
async def analizar_manual(
    dominio_remitente: str = Form(...),
    dominio_ruta_retorno: str = Form(""),
    estado_SPF: str = Form("Aprobado"),
    estado_DKIM: str = Form("Aprobado"),
    destino_enlace: str = Form(""),
    texto_enlace: str = Form(""),
    cuerpo_mensaje: str = Form(""),
    extension_adjunto: str = Form("")
):
    dominio = dominio_remitente.lower()
    edad_dias = analizador_osint.obtener_edad_dominio(dominio)

    correo = {
        "dominio_remitente": dominio,
        "dominio_ruta_retorno": dominio_ruta_retorno.lower(),
        "estado_SPF": estado_SPF,
        "estado_DKIM": estado_DKIM,
        "lista_enlaces_URL": [destino_enlace] if destino_enlace else [],
        "texto_visible_enlace": texto_enlace,
        "destino_real_enlace": destino_enlace,
        "cuerpo_mensaje": cuerpo_mensaje.lower(),
        "extension_adjunto": extension_adjunto.lower(),
        "edad_dominio_dias": edad_dias
    }

    memoria = MemoriaDeTrabajo()
    memoria.cargar_hechos(correo)
    motor.ejecutar_forward_chaining(memoria)

    db.guardar_registro(
        remitente=correo['dominio_remitente'],
        score=memoria.puntaje_riesgo,
        clasificacion=memoria.clasificacion_final,
        tipo_amenaza=memoria.tipo_amenaza,
        reglas=[log['regla'] for log in memoria.reglas_activadas]
    )

    return {
        "status": "success",
        "hechos": correo,
        "resultados": memoria.obtener_estado_actual(),
        "clasificacion": memoria.clasificacion_final,
        "tipo_amenaza": memoria.tipo_amenaza
    }

@app.get("/api/reporte/{analisis_id}")
async def generar_reporte(analisis_id: int):
    historial = db.obtener_historial_completo()
    analisis = None
    for reg in historial:
        if reg.get('id') == analisis_id:
            analisis = reg
            break

    if not analisis:
        return {"status": "error", "message": "Análisis no encontrado"}

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, spaceAfter=20)
    heading_style = ParagraphStyle('Heading', parent=styles['Heading2'], fontSize=14, spaceAfter=10, textColor=colors.HexColor("#1d4ed8"))
    normal_style = styles['Normal']

    elements = []

    elements.append(Paragraph("PhishGuard - Reporte de Análisis de Seguridad", title_style))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(f"Fecha: {analisis.get('created_at', 'N/A')}", normal_style))
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Resumen del Análisis", heading_style))

    data = [
        ["Campo", "Valor"],
        ["ID Análisis", str(analisis.get('id', 'N/A'))],
        ["Remitente", analisis.get('remitente', 'N/A')],
        ["Clasificación", analisis.get('clasificacion', 'N/A')],
        ["Tipo de Amenaza", analisis.get('tipo_amenaza', 'N/A')],
        ["Score de Riesgo", f"{analisis.get('score', 0)}/100"],
    ]

    table = Table(data, colWidths=[2*inch, 4*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1d4ed8")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 20))

    reglas_str = analisis.get('reglas_activadas', '')
    if reglas_str:
        reglas_list = reglas_str.split(',')
        elements.append(Paragraph("Reglas Activadas", heading_style))

        reglas_data = [["Regla", "Descripción"]]
        for regla in reglas_list:
            regla = regla.strip()
            desc = reglas_info.get(regla, {}).get('descripcion', 'N/A')
            peso = reglas_info.get(regla, {}).get('peso_asignado', 0)
            reglas_data.append([f"{regla} (+{peso} pts)", desc])

        table_reglas = Table(reglas_data, colWidths=[1.5*inch, 4.5*inch])
        table_reglas.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#dc2626")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#fef2f2")),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
        ]))
        elements.append(table_reglas)

    elements.append(Spacer(1, 30))
    elements.append(Paragraph("Este reporte fue generado automáticamente por PhishGuard.", normal_style))

    doc.build(elements)

    buffer.seek(0)
    filename = f"phishguard_reporte_{analisis_id}_{datetime.now().strftime('%Y%m%d')}.pdf"

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)