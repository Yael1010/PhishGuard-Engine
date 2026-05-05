import pandas as pd
import re
import email
from email import policy
from osint import AnalizadorOSINT

class ExtractorMasivo:
    def __init__(self):
        # Patrón para encontrar URLs en el texto
        self.patron_url = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        # Inicializamos el analizador OSINT
        self.osint = AnalizadorOSINT()

    def cargar_dataset(self, ruta_csv):
        """Lee el archivo CSV usando Pandas."""
        try:
            df = pd.read_csv(ruta_csv)
            return df
        except Exception as e:
            print(f"Error al leer el archivo CSV: {e}")
            return None

    def extraer_hechos_de_fila(self, fila):
        """Procesa una fila de un dataset CSV."""
        cuerpo = str(fila.get('cuerpo_mensaje', ''))
        if cuerpo == 'nan': cuerpo = ''

        urls_encontradas = self.patron_url.findall(cuerpo)
        enlace_directo = str(fila.get('destino_enlace', ''))
        if enlace_directo != 'nan' and enlace_directo:
            urls_encontradas.append(enlace_directo)

        hechos = {
            "dominio_remitente": str(fila.get('from_domain', '')).lower(),
            "dominio_ruta_retorno": str(fila.get('return_path', '')).lower(),
            "estado_SPF": str(fila.get('spf', 'Aprobado')),
            "estado_DKIM": str(fila.get('dkim', 'Aprobado')),
            "lista_enlaces_URL": urls_encontradas,
            "texto_visible_enlace": str(fila.get('texto_enlace', '')),
            "destino_real_enlace": enlace_directo,
            "cuerpo_mensaje": cuerpo.lower(),
            "extension_adjunto": str(fila.get('adjunto', '')).lower(),
            "edad_dominio_dias": None # Desactivado en lotes para evitar bloqueos de IP
        }
        
        for k, v in hechos.items():
            if v == 'nan': hechos[k] = ''
        return hechos

    def extraer_hechos_de_eml(self, archivo_eml):
        """Lee un archivo .eml real y extrae las variables para PhishGuard."""
        try:
            # Compatibilidad con FastAPI (usando .file) o lectura local
            if hasattr(archivo_eml, 'file'):
                msg = email.message_from_binary_file(archivo_eml.file, policy=policy.default)
            elif hasattr(archivo_eml, 'stream'):
                msg = email.message_from_binary_file(archivo_eml.stream, policy=policy.default)
            else:
                with open(archivo_eml, 'rb') as f:
                    msg = email.message_from_binary_file(f, policy=policy.default)
        except Exception as e:
            print(f"Error procesando .eml: {e}")
            return None

        # 1. Extracción de Cabeceras (Headers)
        from_header = str(msg.get('From', ''))
        dominio_remitente = from_header.split('@')[-1].strip('>').lower() if '@' in from_header else ''

        return_path = str(msg.get('Return-Path', ''))
        dominio_ruta_retorno = return_path.strip('<>').split('@')[-1].lower() if '@' in return_path else ''

        # Buscar resultados de autenticación en las cabeceras invisibles
        auth_results = str(msg.get('Authentication-Results', '')).lower()
        estado_spf = "Fallo" if "spf=fail" in auth_results or "spf=softfail" in auth_results else "Aprobado"
        estado_dkim = "Fallo" if "dkim=fail" in auth_results else "Aprobado"

        # 2. Extracción del Cuerpo del mensaje y URLs
        cuerpo = ""
        if msg.is_multipart():
            for part in msg.walk():
                # Solo extraemos texto plano para el análisis semántico rápido
                if part.get_content_type() == "text/plain":
                    try:
                        cuerpo += part.get_content()
                    except: pass
        else:
            try: cuerpo = msg.get_content()
            except: pass

        urls_encontradas = self.patron_url.findall(cuerpo)

        # 3. Detección de Archivos Adjuntos
        extensiones_adjuntos = []
        for part in msg.iter_attachments():
            nombre_archivo = part.get_filename()
            if nombre_archivo:
                extension = "." + nombre_archivo.split('.')[-1].lower()
                extensiones_adjuntos.append(extension)

        ext_adjunto = extensiones_adjuntos[0] if extensiones_adjuntos else ""
        
        # 4. OSINT: Obtener la edad del dominio en internet
        edad_dias = self.osint.obtener_edad_dominio(dominio_remitente)

        # Formateamos los datos para la Memoria de Trabajo
        return {
            "dominio_remitente": dominio_remitente,
            "dominio_ruta_retorno": dominio_ruta_retorno,
            "estado_SPF": estado_spf,
            "estado_DKIM": estado_dkim,
            "lista_enlaces_URL": urls_encontradas,
            "texto_visible_enlace": "", # Difícil de extraer de un txt plano sin HTML
            "destino_real_enlace": urls_encontradas[0] if urls_encontradas else "",
            "cuerpo_mensaje": cuerpo.lower(),
            "extension_adjunto": ext_adjunto,
            "edad_dominio_dias": edad_dias
        }